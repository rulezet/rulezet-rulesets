rule _20160921_ded524cdc972424d0fa8254648795d71_20160921_e98813a05e66_1750 {
  meta:
    description = "datamaliciousorder - from files 20160921_ded524cdc972424d0fa8254648795d71.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"
    hash2       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"

  strings:
    $s1  = "){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"ZFe\";})" ascii
    $s2  = ")(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s3  = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SEo\";})()," ascii
    $s4  = "{return \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yi\";})()" ascii
    $s5  = " f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Q" ascii
    $s6  = "turn \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s7  = "})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s8  = "tion f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii
    $s9  = "Gn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RVb\";})(),(functio" ascii
    $s10 = ")(),(function f000(){return \"ZGq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"YTp\";})(),(function f00" ascii
    $s11 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZGq\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}