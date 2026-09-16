rule sig_20170420_ad0b38af5cd1190540120802822bbe05 {
  meta:
    description = "datamaliciousorder - file 20170420_ad0b38af5cd1190540120802822bbe05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b29d4462ff5d00a65112374ab86d2951226443ff9d7dfa75ca6d7fd8dddceda"

  strings:
    $s1 = "return LlQfnKbNXDxqFoeSwdG.split(mkQsPIxpgNbludT).join(\"\"); }" fullword ascii
    $s2 = "if (ACkSMjarLFIvcuPtNOn.FolderExists(\"C\"+\":\\\\W\"+\"iNdO\"+\"Ws\") == true) {" fullword ascii
    $s3 = "function RLlNKhCOYVrUDkBA(LlQfnKbNXDxqFoeSwdG, mkQsPIxpgNbludT) { " fullword ascii
    $s4 = "function pAIrjiuyQDkPdavh(fldtmvNrayqTuxIkKgo) { return String.fromCharCode(fldtmvNrayqTuxIkKgo); }" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}