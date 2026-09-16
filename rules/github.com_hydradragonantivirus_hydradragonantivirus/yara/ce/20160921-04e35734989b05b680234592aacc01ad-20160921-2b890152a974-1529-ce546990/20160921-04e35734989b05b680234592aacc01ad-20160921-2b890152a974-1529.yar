rule _20160921_04e35734989b05b680234592aacc01ad_20160921_2b890152a974_1529 {
  meta:
    description = "datamaliciousorder - from files 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js, 20160921_5e30fe0c691277f3c6d0814d796ba918.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash2       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash3       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"
    hash4       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"

  strings:
    $s1  = "n \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(fu" ascii
    $s2  = "uck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq" ascii
    $s3  = "{return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s4  = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return " ascii
    $s5  = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Ot\";})(),(f" ascii
    $s6  = "return \"To\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s7  = "fuck(){return \"Wo0\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NK" ascii
    $s8  = "rn \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(fun" ascii
    $s9  = "\"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(functi" ascii
    $s10 = "unction fuck(){return \"Ot\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){retur" ascii
    $s11 = "urn \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Za\";})(),(" ascii
    $s12 = "(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}