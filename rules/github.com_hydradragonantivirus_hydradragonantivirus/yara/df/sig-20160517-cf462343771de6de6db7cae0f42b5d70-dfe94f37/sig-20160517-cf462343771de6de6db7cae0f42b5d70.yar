rule sig_20160517_cf462343771de6de6db7cae0f42b5d70 {
  meta:
    description = "datamaliciousorder - file 20160517_cf462343771de6de6db7cae0f42b5d70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10114dc4845c9c7a5125acae408489d3bcf9e1fbce5bb07ea53d867236ea158d"

  strings:
    $s1 = "var jak='votixbapib3yryogxq jyryfzptjjlxhraq2janvqkxwdxbgkrtycqiyaog3mjsvibgz1xkqettduk=bvrq1\\'mmu1stzqw42cz3tulnfblwqiyvjjpfnc" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}