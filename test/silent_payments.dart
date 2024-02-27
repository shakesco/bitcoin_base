// ignore_for_file: non_constant_identifier_names
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:bitcoin_base/src/bitcoin/script/outpoint.dart';
import 'package:bitcoin_base/src/bitcoin/script/scripts.dart';
import 'package:bitcoin_base/src/bitcoin/address/address.dart';
import 'package:bitcoin_base/src/bitcoin/silent_payments/silent_payments.dart';
import 'package:bitcoin_base/src/crypto/crypto.dart';
import 'package:blockchain_utils/blockchain_utils.dart';
import 'package:test/test.dart';

// G , needed for generating the labels "database"
final G = ECPublic.fromBytes(BigintUtils.toBytes(Curves.generatorSecp256k1.x, length: 32));

main() {
  group('Silent Payment Addresses', () {
    // const scanKey = '036a1035a192f8f5fd375556f36ea4abc387361d32c709831ec624a5b73d0b7b9d';
    // const spendKey = '028eaf19db65cece905cf2b3eab811148d6fe874089a4a68e5d8b0a1a0904f6bd0';
    // const silentAddress =
    'sprt1qqd4pqddpjtu0tlfh24t0xm4y40pcwdsaxtrsnqc7ccj2tdeapdae6q5w4uvakewwe6g9eu4na2upz9yddl58gzy6ff5wtk9s5xsfqnmt6q30zssg';

    // test('can encode scan and spend key to silent payment address', () {
    //   expect(
    //       SilentPaymentAddress(
    //         scanPubkey: ECPublic.fromHex(scanKey),
    //         spendPubkey: ECPublic.fromHex(spendKey),
    //         hrp: 'sprt',
    //         version: 0,
    //       ).toString(),
    //       silentAddress);
    // });
    // test('can decode scan and spend key from silent payment address', () {
    //   expect(
    //       SilentPaymentAddress.fromAddress(silentAddress).toString(),
    //       SilentPaymentAddress(
    //               scanPubkey: ECPublic.fromHex(scanKey),
    //               spendPubkey: ECPublic.fromHex(spendKey),
    //               hrp: 'sprt',
    //               version: 0)
    //           .toString());
    // });

    // test('can derive scan and spend key from master key', () async {
    //   const mnemonic =
    //       'praise you muffin lion enable neck grocery crumble super myself license ghost';
    //   final address = SilentPaymentOwner.fromMnemonic(mnemonic);

    //   final seed = Bip39MnemonicDecoder().decode(mnemonic);
    //   final root = Bip32Slip10Secp256k1.fromSeed(seed, Bip32Const.testNetKeyNetVersions);

    //   expect(address.scanPrivkey.toHex(), root.derivePath(SCAN_PATH).privateKey.toHex());
    //   expect(address.scanPubkey.toHex(), root.derivePath(SCAN_PATH).publicKey.toHex());

    //   expect(address.spendPrivkey.toHex(), root.derivePath(SPEND_PATH).privateKey.toHex());
    //   expect(address.spendPubkey.toHex(), root.derivePath(SPEND_PATH).publicKey.toHex());
    // });

    // test('can create a labeled silent payment address', () {
    //   final given = [
    //     [
    //       '0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4',
    //       '025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36',
    //       '0000000000000000000000000000000000000000000000000000000000000001',
    //       'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqah4hxfsjdwyaeel4g8x2npkj7qlvf2692l5760z5ut0ggnlrhdzsy3cvsj',
    //     ],
    //     [
    //       '0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4',
    //       '025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36',
    //       '0000000000000000000000000000000000000000000000000000000000000539',
    //       'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq562yg7htxyg8eq60rl37uul37jy62apnf5ru62uef0eajpdfrnp5cmqndj',
    //     ],
    //     [
    //       '03b4cc0b090b6f49a684558852db60ee5eb1c5f74352839c3d18a8fc04ef7354e0',
    //       '03bc95144daf15336db3456825c70ced0a4462f89aca42c4921ee7ccb2b3a44796',
    //       '91cb04398a508c9d995ff4a18e5eae24d5e9488309f189120a3fdbb977978c46',
    //       'sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqll5497pp2gcr4cmq0v5nv07x8u5jswmf8ap2q0kxmx8628mkqanyu63ck8',
    //     ],
    //   ];

    //   for (final data in given) {
    //     final scanKey = data[0];
    //     final spendKey = data[1];
    //     final label = data[2];
    //     final address = data[3];
    //     final result = SilentPaymentAddress(
    //             B_scan: ECPublic.fromHex(scanKey), B_spend: ECPublic.fromHex(spendKey))
    //         .createLabeledSilentPaymentAddress(ECPublic.fromHex(scanKey),
    //             ECPublic.fromHex(spendKey), BigintUtils.fromBytes(BytesUtils.fromHexString(label)));

    //     expect(result.toString(), address);
    //   }
    // });
  });

  final fixtures =
      json.decode(File('test/fixtures/silent_payments.json').readAsStringSync(encoding: utf8));

  for (var testCase in fixtures) {
    test(testCase['comment'], () {
      Map<String, List<SilentPaymentOutput>> sendingOutputs = {};

      // Test sending
      for (var sendingTest in testCase['sending']) {
        List<Outpoint> vinOutpoints = [];
        List<ECPrivateInfo> inputPrivKeyInfos = [];
        List<ECPublic> inputPubKeys = [];

        var given = sendingTest["given"];

        for (var input in given['vin']) {
          final prevoutScript = Script.fromRaw(hexData: input['prevout']['scriptPubKey']['hex']);
          final privkey = ECPrivate.fromHex(input['private_key']);

          final vin = VinInfo(
            outpoint: Outpoint(txid: input['txid'], index: input['vout']),
            scriptSig: BytesUtils.fromHexString(input['scriptSig']),
            txinwitness: TxWitnessInput(
                stack: [],
                scriptWitness: ScriptWitness(
                    stack: deserStringVector(
                  ByteData.sublistView(
                    Uint8List.fromList(
                      BytesUtils.fromHexString(input['txinwitness']),
                    ),
                  ),
                ))),
            prevOutScript: prevoutScript,
            privkey: privkey,
          );

          vinOutpoints.add(vin.outpoint);

          final pubkey = getPubkeyFromInput(vin);

          if (pubkey == null) {
            continue;
          }

          inputPrivKeyInfos
              .add(ECPrivateInfo(privkey, prevoutScript.getAddressType() == SegwitAddresType.p2tr));
          inputPubKeys.add(pubkey);
        }

        if (inputPubKeys.isNotEmpty) {
          List<SilentPaymentDestination> silentPaymentDestinations =
              (given['recipients'] as List<dynamic>)
                  .map((recipient) =>
                      SilentPaymentDestination.fromAddress(recipient[0], recipient[1].floor()))
                  .toList();

          final spb = SilentPaymentBuilder(pubkeys: inputPubKeys, outpoints: vinOutpoints);
          sendingOutputs = spb.createOutputs(inputPrivKeyInfos, silentPaymentDestinations);

          List<dynamic> expectedDestinations = sendingTest['expected']['outputs'];

          silentPaymentDestinations.forEach((destination) {
            final generatedOutputs = sendingOutputs[destination.toString()];
            expect(generatedOutputs != null, true);

            for (final output in generatedOutputs!) {
              final generatedPubkey = output.address.pubkey!;
              final expectedPubkey = expectedDestinations.firstWhere((expected) =>
                  BytesUtils.toHexString(generatedPubkey.toCompressedBytes().sublist(1)) ==
                  expected[0]);

              expect(expectedPubkey != null, true);
            }
          });
        }
      }

      final msg = SHA256().update(utf8.encode('message')).digest();
      final aux = SHA256().update(utf8.encode('random auxiliary data')).digest();

      // Test receiving
      for (final receivingTest in testCase['receiving']) {
        List<Outpoint> vinOutpoints = [];
        List<ECPublic> inputPubKeys = [];

        final given = receivingTest["given"];
        final expected = receivingTest['expected'];

        List<ECPublic> outputsToCheck =
            (given['outputs'] as List<dynamic>).map((output) => ECPublic.fromHex(output)).toList();

        final receivingAddresses = [];

        final silentPaymentOwner = SilentPaymentOwner.fromPrivateKeys(
            b_scan: ECPrivate.fromHex(given["key_material"]["scan_priv_key"]),
            b_spend: ECPrivate.fromHex(given["key_material"]["spend_priv_key"]));

        // Add change address
        receivingAddresses.add(silentPaymentOwner);

        Map<String, String>? preComputedLabels;
        for (var label in given['labels']) {
          receivingAddresses.add(silentPaymentOwner.toLabeledSilentPaymentAddress(label));
          final generatedLabel = silentPaymentOwner.generateLabel(label);

          preComputedLabels ??= {};
          preComputedLabels[G.tweakMul(BigintUtils.fromBytes(generatedLabel)).toHex()] =
              BytesUtils.toHexString(generatedLabel);
        }

        for (var address in receivingAddresses) {
          expect(address.toString(), expected['addresses'][receivingAddresses.indexOf(address)]);
        }

        for (var input in given['vin']) {
          final prevoutScript = Script.fromRaw(hexData: input['prevout']['scriptPubKey']['hex']);

          final vin = VinInfo(
            outpoint: Outpoint(txid: input['txid'], index: input['vout']),
            scriptSig: BytesUtils.fromHexString(input['scriptSig']),
            txinwitness: TxWitnessInput(
                stack: [],
                scriptWitness: ScriptWitness(
                    stack: deserStringVector(
                  ByteData.sublistView(
                    Uint8List.fromList(
                      BytesUtils.fromHexString(input['txinwitness']),
                    ),
                  ),
                ))),
            prevOutScript: prevoutScript,
          );

          final pubkey = getPubkeyFromInput(vin);

          if (pubkey == null) {
            return;
          }

          vinOutpoints.add(vin.outpoint);
          inputPubKeys.add(pubkey);
        }

        if (inputPubKeys.isNotEmpty) {
          final spb = SilentPaymentBuilder(pubkeys: inputPubKeys, outpoints: vinOutpoints);

          final addToWallet = spb.scanOutputs(
              silentPaymentOwner.b_scan, silentPaymentOwner.B_spend, outputsToCheck,
              precomputedLabels: preComputedLabels);

          final expectedDestinations = expected['outputs'];

          // Check that the private key is correct for the found output public key
          for (int i = 0; i < expectedDestinations.length; i++) {
            final output = addToWallet.entries.elementAt(i);
            final pubkey = output.key;
            final expectedPubkey = expectedDestinations[i]["pub_key"];
            expect(BytesUtils.toHexString(BytesUtils.fromHexString(pubkey).sublist(1)),
                expectedPubkey);

            final privKeyTweak = output.value[0];
            final expectedPrivKeyTweak = expectedDestinations[i]["priv_key_tweak"];
            expect(privKeyTweak, expectedPrivKeyTweak);

            final fullPrivateKey =
                silentPaymentOwner.b_spend.clone().tweakAdd(BigintUtils.parse(privKeyTweak));

            if (fullPrivateKey.toBytes()[0] == 0x03) {
              fullPrivateKey.negate();
            }

            // Sign the message with schnorr
            final btcSigner = BitcoinSigner.fromKeyBytes(fullPrivateKey.toBytes());
            List<int> sig =
                btcSigner.signSchnorrTransaction(msg, tapScripts: [], tweak: false, aux: aux);

            // Verify the message is correct
            expect(btcSigner.verifyKey.verifySchnorr(msg, sig, isTweak: false), true);

            // Verify the signature is correct
            expect(BytesUtils.toHexString(sig), expectedDestinations[i]["signature"]);

            i++;
          }
        }
      }
    });
  }
}
