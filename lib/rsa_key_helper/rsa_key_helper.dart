import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:asn1lib/asn1lib.dart';

List<int> decodePEM(String pem) {
  final startsWith = [
    '-----BEGIN PUBLIC KEY-----',
    '-----BEGIN PRIVATE KEY-----',
    '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n',
    '-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n',
  ];
  final endsWith = [
    '-----END PUBLIC KEY-----',
    '-----END PRIVATE KEY-----',
    '-----END PGP PUBLIC KEY BLOCK-----',
    '-----END PGP PRIVATE KEY BLOCK-----',
  ];
  final isOpenPgp = pem.contains('BEGIN PGP');

  for (final s in startsWith) {
    if (pem.startsWith(s)) {
      pem = pem.substring(s.length);
    }
  }

  for (final s in endsWith) {
    if (pem.endsWith(s)) {
      pem = pem.substring(0, pem.length - s.length);
    }
  }

  if (isOpenPgp) {
    final index = pem.indexOf('\r\n');
    pem = pem.substring(0, index);
  }

  pem = pem.replaceAll('\n', '');
  pem = pem.replaceAll('\r', '');

  return base64.decode(pem);
}

class RsaKeyHelper {
  AsymmetricKeyPair<PublicKey, PrivateKey> generateKeyPair() {
    // AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateKeyPair() {
    final keyParams =
        RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 12);

    final secureRandom = FortunaRandom();
    final random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    final rngParams = ParametersWithRandom(keyParams, secureRandom);
    final k = RSAKeyGenerator();
    k.init(rngParams);

    final keyPair = k.generateKeyPair();
    // as AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>;

    return keyPair;
  }

  String encrypt(String plaintext, RSAPublicKey publicKey) {
    final cipher = RSAEngine()
      ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    final cipherText = cipher.process(Uint8List.fromList(plaintext.codeUnits));

    return String.fromCharCodes(cipherText);
  }

  String decrypt(String ciphertext, RSAPrivateKey privateKey) {
    final cipher = RSAEngine()
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final decrypted = cipher.process(Uint8List.fromList(ciphertext.codeUnits));

    return String.fromCharCodes(decrypted);
  }

  parsePublicKeyFromPem(pemString) {
    List<int> publicKeyDER = decodePEM(pemString);
    final asn1Parser = ASN1Parser(Uint8List.fromList(publicKeyDER));
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    final publicKeyBitString = topLevelSeq.elements[1];

    final publicKeyAsn =
        ASN1Parser(publicKeyBitString.contentBytes() ?? Uint8List(0));
    // ASN1Sequence publicKeySeq = publicKeyAsn.nextObject();
    ASN1Sequence publicKeySeq = ASN1Sequence();
    publicKeySeq.add(publicKeyAsn.nextObject());

    final modulus = publicKeySeq.elements[0] as ASN1Integer;
    final exponent = publicKeySeq.elements[1] as ASN1Integer;

    RSAPublicKey rsaPublicKey = RSAPublicKey(
        modulus.valueAsBigInteger ?? BigInt.zero,
        exponent.valueAsBigInteger ?? BigInt.zero);

    return rsaPublicKey;
  }

  parsePrivateKeyFromPem(pemString) {
    List<int> privateKeyDER = decodePEM(pemString);
    var asn1Parser = ASN1Parser(Uint8List.fromList(privateKeyDER));
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    var version = topLevelSeq.elements[0];
    final algorithm = topLevelSeq.elements[1];
    final privateKey = topLevelSeq.elements[2];

    asn1Parser = ASN1Parser(privateKey.contentBytes() ?? Uint8List(0));
    final pkSeq = asn1Parser.nextObject() as ASN1Sequence;

    version = pkSeq.elements[0];
    final modulus = pkSeq.elements[1] as ASN1Integer;
    final publicExponent = pkSeq.elements[2] as ASN1Integer;
    final privateExponent = pkSeq.elements[3] as ASN1Integer;
    final p = pkSeq.elements[4] as ASN1Integer;
    final q = pkSeq.elements[5] as ASN1Integer;
    final exp1 = pkSeq.elements[6] as ASN1Integer;
    final exp2 = pkSeq.elements[7] as ASN1Integer;
    final co = pkSeq.elements[8] as ASN1Integer;

    RSAPrivateKey rsaPrivateKey = RSAPrivateKey(
        modulus.valueAsBigInteger ?? BigInt.from(0),
        privateExponent.valueAsBigInteger ?? BigInt.from(0),
        p.valueAsBigInteger,
        q.valueAsBigInteger);

    return rsaPrivateKey;
  }

  encodePublicKeyToPem(RSAPublicKey publicKey) {
    final algorithmSeq = ASN1Sequence();
    final algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    final paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSeq.add(algorithmAsn1Obj);
    algorithmSeq.add(paramsAsn1Obj);

    final publicKeySeq = ASN1Sequence();
    publicKeySeq.add(ASN1Integer(publicKey.modulus ?? BigInt.zero));
    publicKeySeq.add(ASN1Integer(publicKey.exponent ?? BigInt.zero));
    final publicKeySeqBitString =
        ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

    final topLevelSeq = ASN1Sequence();
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeySeqBitString);
    final dataBase64 = base64.encode(topLevelSeq.encodedBytes);

    return '''-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----''';
  }

  encodePrivateKeyToPem(RSAPrivateKey privateKey) {
    final version = ASN1Integer(BigInt.from(0));

    final algorithmSeq = ASN1Sequence();
    final algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
    final paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSeq.add(algorithmAsn1Obj);
    algorithmSeq.add(paramsAsn1Obj);

    final privateKeySeq = ASN1Sequence();
    final modulus = ASN1Integer(privateKey.n ?? BigInt.zero);
    final publicExponent = ASN1Integer(BigInt.parse('65537'));
    final privateExponent = ASN1Integer(privateKey.d ?? BigInt.zero);
    final p = ASN1Integer(privateKey.p ?? BigInt.zero);
    final q = ASN1Integer(privateKey.q ?? BigInt.zero);
    final dP = (privateKey.d ?? BigInt.zero) %
        ((privateKey.p ?? BigInt.zero) - BigInt.from(1));
    final exp1 = ASN1Integer(dP);
    final dQ = (privateKey.d ?? BigInt.zero) %
        ((privateKey.q ?? BigInt.zero) - BigInt.from(1));
    final exp2 = ASN1Integer(dQ);
    final iQ =
        privateKey.q?.modInverse(privateKey.p ?? BigInt.zero) ?? BigInt.zero;
    final co = ASN1Integer(iQ);

    privateKeySeq.add(version);
    privateKeySeq.add(modulus);
    privateKeySeq.add(publicExponent);
    privateKeySeq.add(privateExponent);
    privateKeySeq.add(p);
    privateKeySeq.add(q);
    privateKeySeq.add(exp1);
    privateKeySeq.add(exp2);
    privateKeySeq.add(co);
    final publicKeySeqOctetString =
        ASN1OctetString(Uint8List.fromList(privateKeySeq.encodedBytes));

    final topLevelSeq = ASN1Sequence();
    topLevelSeq.add(version);
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeySeqOctetString);
    final dataBase64 = base64.encode(topLevelSeq.encodedBytes);

    return '''-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----''';
  }
}
