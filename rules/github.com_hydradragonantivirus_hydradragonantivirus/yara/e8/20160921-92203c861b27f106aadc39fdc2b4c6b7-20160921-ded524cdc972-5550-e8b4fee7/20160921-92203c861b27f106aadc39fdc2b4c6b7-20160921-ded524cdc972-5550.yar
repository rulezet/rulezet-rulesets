rule _20160921_92203c861b27f106aadc39fdc2b4c6b7_20160921_ded524cdc972_5550 {
  meta:
    description = "datamaliciousorder - from files 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash2       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "nction f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s2 = "on f000(){return \"MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return " ascii
    $s3 = "(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000" ascii
    $s4 = "\"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s5 = "urn \"NBs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}