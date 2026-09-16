rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_da4ec6dae2ec_3266 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = "on f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = "on f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s3 = "{return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";}" ascii
    $s4 = "0(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s5 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){retu" ascii
    $s6 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}