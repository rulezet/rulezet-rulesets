rule _20160921_539bde925d7d117e6c387c1b32dd397b_20160921_e1bc53e337e2_5188 {
  meta:
    description = "datamaliciousorder - from files 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash2       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"
    hash3       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "ion f000(){return \"SGs\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s2 = "00(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\"" ascii
    $s3 = "(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(" ascii
    $s4 = "ction f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"YTp\";})(),(function f000(){retur" ascii
    $s5 = "n f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}