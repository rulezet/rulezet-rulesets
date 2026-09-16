rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_539bde925d7d_4700 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash3       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash4       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "000(){return \"Iq\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Do\"" ascii
    $s2 = "unction f000(){return \"SGs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s3 = "n \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(fun" ascii
    $s4 = "(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000()" ascii
    $s5 = "n f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}