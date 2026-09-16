rule _20160921_2eacd3ef1ce6866325342ce8cba80e38_20160921_95ced062e055_4824 {
  meta:
    description = "datamaliciousorder - from files 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash2       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash3       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash4       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash5       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash6       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"

  strings:
    $s1 = "(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000()" ascii
    $s2 = "00(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv" ascii
    $s3 = "on f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return " ascii
    $s4 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(functi" ascii
    $s5 = "n \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}