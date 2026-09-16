rule _20160921_86391eeb92939f7926213db5cee16e4d_20160921_f1aea308b200_1612 {
  meta:
    description = "datamaliciousorder - from files 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash2       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1  = "000(){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi" ascii
    $s2  = "00(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MDb\"" ascii
    $s3  = "ction f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retur" ascii
    $s4  = "{return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mc\";})(" ascii
    $s5  = "(function f000(){return \"DYx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){" ascii
    $s6  = "b\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(function" ascii
    $s7  = " f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RP" ascii
    $s8  = "nction f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s9  = "ion f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DNa\";})(),(function f000(){return" ascii
    $s10 = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s11 = "{return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(" ascii
    $s12 = "eturn \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DNa\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}