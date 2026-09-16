rule _20160921_53ea150fd63a4ef657412c858a71a13e_20160921_8c33029db614_2441 {
  meta:
    description = "datamaliciousorder - from files 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js, 20160921_97fcc16be1aae58b311e71df667be641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash2       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash3       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"
    hash4       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"

  strings:
    $s1 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f0" ascii
    $s2 = "turn \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})()," ascii
    $s3 = "Eo\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s4 = "unction f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){ret" ascii
    $s5 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii
    $s6 = "{return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(" ascii
    $s7 = "eturn \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})()," ascii
    $s8 = "ction f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}