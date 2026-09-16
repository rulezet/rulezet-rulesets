rule sig_20160525_8c692ea8ef53323c70ab3af835511487 {
  meta:
    description = "datamaliciousorder - file 20160525_8c692ea8ef53323c70ab3af835511487.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6139e0fa3a587e41b0e41100ec77b5a97e017177832dfb56a656704af5c20c19"

  strings:
    $s1 = " rav\\n;)0(]\"tArah\"+\"36x\\\\\"+\"\"[gedotdark = ecapsetihwxelfk rav;\"Zbyh\" = gedotdark rav\\n;\"l35x\\\\\" = modnark rav\\n" ascii
    $s2 = "BDf4x\\\\DA\" = gedotdars rav\\n;\"tSe2x\\\\\" = keppels rav\\n;\"d6x\\\\a56x\\\\r\" = ecapsetihwxelfs rav\\n;\"p97x\\\\t\" = de" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}