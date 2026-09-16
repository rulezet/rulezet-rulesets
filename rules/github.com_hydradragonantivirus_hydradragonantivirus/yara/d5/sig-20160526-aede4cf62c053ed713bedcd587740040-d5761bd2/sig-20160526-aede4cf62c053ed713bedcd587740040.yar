rule sig_20160526_aede4cf62c053ed713bedcd587740040 {
  meta:
    description = "datamaliciousorder - file 20160526_aede4cf62c053ed713bedcd587740040.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "396f67de93c3abc05d732af8d861c03059e3aaffa6fa23170f806810b36fe35f"

  strings:
    $s1 = "fISC rav\\n\\r;\"bOe\" = 4wMMR rav\\n\\r;\"cej\" = cXHC rav\\n\\r;\"t\" = 1tYHU rav\\n\\r;\"BDODA\" = 3vQEY rav\\n\\r;\"tS.\" = " ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}