rule Trojan_Autorun_Trojan_GenericKDZ_94847_174_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_174_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0e705db214684cd7b66daeb630ebef8389daf2ed8bea49294fc2ffff4dda283"

  strings:
    $s1 = "enumerate(DataLoader)#_SingleProcessDataLoaderIter.__next__" fullword ascii
    $s2 = "image::write_file(str _0, Tensor _1) -> " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}