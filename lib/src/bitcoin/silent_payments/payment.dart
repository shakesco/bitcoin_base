// ignore_for_file: non_constant_identifier_names
part of 'package:bitcoin_base/src/bitcoin/silent_payments/silent_payments.dart';

class SilentPaymentOutput {
  final P2trAddress address;
  final int amount;

  SilentPaymentOutput(this.address, this.amount);
}

class ECPrivateInfo {
  final ECPrivate privkey;
  final bool isTaproot;

  ECPrivateInfo(this.privkey, this.isTaproot);
}

class SilentPaymentBuilder {
  final List<Outpoint>? outpoints;
  final List<ECPublic>? pubkeys;
  late ECPublic A_sum;
  late List<int> inputHash;
  String? receiverTweak;

  SilentPaymentBuilder({
    this.outpoints,
    this.pubkeys,
    this.receiverTweak,
  }) {
    if (receiverTweak == null) {
      _getAsum();
      _getInputHash();
    }
  }

  void _getAsum() {
    final head = pubkeys!.first;
    final tail = pubkeys!.sublist(1);

    A_sum = tail.fold<ECPublic>(head, (acc, item) => ECPublic(acc.publicKey).pubkeyAdd(item));
  }

  void _getInputHash() {
    final sortedOutpoints = <List<int>>[];

    for (final outpoint in outpoints!) {
      final vout = outpoint.index;

      sortedOutpoints.add(BytesUtils.concatBytes([
        BytesUtils.fromHexString(outpoint.txid).reversed.toList(),
        BigintUtils.toBytes(BigInt.from(vout), length: 4, order: Endian.little)
      ]));
    }

    sortedOutpoints.sort(BytesUtils.compareBytes);
    final lowestOutpoint = sortedOutpoints.first;

    inputHash = taggedHash(
        BytesUtils.concatBytes([lowestOutpoint, A_sum.toCompressedBytes()]), "BIP0352/Inputs");
  }

  Map<String, List<SilentPaymentOutput>> createOutputs(
    List<ECPrivateInfo> inputPrivKeyInfos,
    List<SilentPaymentDestination> silentPaymentDestinations,
  ) {
    ECPrivate? a_sum;

    for (final info in inputPrivKeyInfos) {
      final key = info.privkey;
      final isTaproot = info.isTaproot;

      var k = ECPrivate(key.prive);

      if (isTaproot && key.getPublic().publicKey.point.y % BigInt.two != BigInt.zero) {
        k = k.negate();
      }

      if (a_sum == null) {
        a_sum = k;
      } else {
        a_sum = a_sum.tweakAdd(BigintUtils.fromBytes(k.toBytes()));
      }
    }

    Map<String, Map<String, List<SilentPaymentDestination>>> silentPaymentGroups = {};

    for (final silentPaymentDestination in silentPaymentDestinations) {
      final B_scan = silentPaymentDestination.B_scan;
      final B_scan_hex = B_scan.toHex();

      if (silentPaymentGroups.containsKey(B_scan_hex)) {
        // Current key already in silentPaymentGroups, simply add up the new destination
        // with the already calculated ecdhSharedSecret
        final group = silentPaymentGroups[B_scan_hex]!;
        final ecdhSharedSecret = group.keys.first;
        final recipients = group.values.first;

        silentPaymentGroups[B_scan_hex] = {
          ecdhSharedSecret: [...recipients, silentPaymentDestination]
        };
      } else {
        final senderPartialSecret =
            a_sum!.clone().tweakMul(BigintUtils.fromBytes(inputHash)).toBytes();

        final ecdhSharedSecret =
            B_scan.clone().tweakMul(BigintUtils.fromBytes(senderPartialSecret)).toHex();

        silentPaymentGroups[B_scan_hex] = {
          ecdhSharedSecret: [silentPaymentDestination]
        };
      }
    }

    // Result destinations with amounts
    // { <silentPaymentAddress>: [(<tweakedPubKey1>, <amount>), (<tweakedPubKey2>, <amount>)...] }
    Map<String, List<SilentPaymentOutput>> result = {};
    for (final group in silentPaymentGroups.entries) {
      final ecdhSharedSecret = group.value.keys.first;
      final destinations = group.value.values.first;

      int k = 0;
      for (final destination in destinations) {
        final t_k = taggedHash(
            BytesUtils.concatBytes([
              ECPublic.fromHex(ecdhSharedSecret).toCompressedBytes(),
              BigintUtils.toBytes(BigInt.from(k), length: 4)
            ]),
            "BIP0352/SharedSecret");

        final P_mn = ECPublic(destination.B_spend.publicKey).tweakAdd(BigintUtils.fromBytes(t_k));

        if (result.containsKey(destination.toString())) {
          result[destination.toString()]!
              .add(SilentPaymentOutput(P_mn.toTaprootAddress(), destination.amount));
        } else {
          result[destination.toString()] = [
            SilentPaymentOutput(P_mn.toTaprootAddress(), destination.amount)
          ];
        }

        k++;
      }
    }

    return result;
  }

  Map<String, List<String>> scanOutputs(
      ECPrivate b_scan, ECPublic B_spend, List<String> outputsToCheck,
      {Map<String, String>? precomputedLabels}) {
    final tweakDataForRecipient = receiverTweak != null
        ? ECPublic.fromHex(receiverTweak!)
        : A_sum.clone().tweakMul(BigintUtils.fromBytes(inputHash));
    final ecdhSharedSecret = tweakDataForRecipient.tweakMul(b_scan.toBigInt());

    final matches = <String, List<String>>{};
    var k = 0;

    do {
      final t_k = taggedHash(
          BytesUtils.concatBytes([
            ecdhSharedSecret.toCompressedBytes(),
            BigintUtils.toBytes(BigInt.from(k), length: 4, order: Endian.big)
          ]),
          "BIP0352/SharedSecret");

      final P_k = B_spend.clone().tweakAdd(BigintUtils.fromBytes(t_k));
      final length = outputsToCheck.length;

      for (var i = 0; i < length; i++) {
        final output = outputsToCheck[i];

        if (output == P_k.toTaprootAddress().toScriptPubKey().toHex() ||
            (BytesUtils.compareBytes(ECPublic.fromHex(output).toCompressedBytes().sublist(1),
                    P_k.toCompressedBytes().sublist(1)) ==
                0)) {
          matches[P_k.toHex()] = [BytesUtils.toHexString(t_k)];
          outputsToCheck.removeAt(i);
          k++;
          break;
        }

        if (precomputedLabels != null && precomputedLabels.isNotEmpty) {
          var m_G_sub = ECPublic.fromHex(output).pubkeyAdd(P_k.clone().negate());
          var m_G = precomputedLabels[m_G_sub.toHex()];

          if (m_G == null) {
            m_G_sub = ECPublic.fromHex(output).negate().pubkeyAdd(P_k.clone().negate());
            m_G = precomputedLabels[m_G_sub.toHex()];
          }

          if (m_G != null) {
            final P_km = P_k.clone().tweakAdd(BigintUtils.fromBytes(BytesUtils.fromHexString(m_G)));

            matches[P_km.toHex()] = [
              ECPrivate.fromBytes(t_k)
                  .tweakAdd(BigintUtils.fromBytes(BytesUtils.fromHexString(m_G)))
                  .toHex(),
              m_G
            ];

            outputsToCheck.removeAt(i);
            k++; // Increment counter
            break;
          }
        }

        outputsToCheck.removeAt(i);

        if (i + 1 >= outputsToCheck.length) {
          break;
        }
      }
    } while (outputsToCheck.isNotEmpty);

    return matches;
  }
}
