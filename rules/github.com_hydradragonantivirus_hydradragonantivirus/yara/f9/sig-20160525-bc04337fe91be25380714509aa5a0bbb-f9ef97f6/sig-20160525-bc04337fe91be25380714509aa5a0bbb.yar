rule sig_20160525_bc04337fe91be25380714509aa5a0bbb {
  meta:
    description = "datamaliciousorder - file 20160525_bc04337fe91be25380714509aa5a0bbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1be71eb74fb171b2c15d42883828541c9ddc62daaa77e31e74f83dc1b25c0a4c"

  strings:
    $s1 = "anbmuhtom(ssorcam noitcnuf\\n;\"37x\\\\olc\" = eixodn rav\\n;)3(]\"\"+\"47x\\\\\"+\"Arahc\"[imm = gsmn rav;\"eUTD\" = imm rav\\n" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}