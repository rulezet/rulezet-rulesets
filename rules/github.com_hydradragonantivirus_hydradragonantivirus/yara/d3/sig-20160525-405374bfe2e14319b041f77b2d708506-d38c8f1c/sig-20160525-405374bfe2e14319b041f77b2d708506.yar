rule sig_20160525_405374bfe2e14319b041f77b2d708506 {
  meta:
    description = "datamaliciousorder - file 20160525_405374bfe2e14319b041f77b2d708506.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca95c434c4428e10521a16650c2fb422a980dafe05e1deb48d1cea313e17e0d7"

  strings:
    $s1 = "dari + mi + dnenoisilloci + suidarelcitrapi ,imh + )rerednerh(eixodi + cthh + tsilslianbmuhtoh + ssorcah + sdneth + deerdh + mod" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}