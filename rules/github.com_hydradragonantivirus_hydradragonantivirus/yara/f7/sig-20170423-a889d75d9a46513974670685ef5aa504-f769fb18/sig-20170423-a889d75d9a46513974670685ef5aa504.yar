rule sig_20170423_a889d75d9a46513974670685ef5aa504 {
  meta:
    description = "datamaliciousorder - file 20170423_a889d75d9a46513974670685ef5aa504.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab03be3be1e9180eecb0f595aec6d647bba833b9ee88839c6069e4a7b889acbd"

  strings:
    $s1 = "if (OmEDyKgHiAknrjVh.FolderExists(\"C:\\\\w\"+\"inD\"+\"OWs\") == true) {" fullword ascii
    $s2 = "return kYFwJBTUHpsRSxh.split(RwTlcsrbkEdfviYneB).join(icotBIJnvDCXklLRja); }" fullword ascii
    $s3 = "function haYcbJKtynvpLEu(kYFwJBTUHpsRSxh, RwTlcsrbkEdfviYneB, icotBIJnvDCXklLRja) { " fullword ascii
    $s4 = "\"al(un?scap?(\\\"var:20wsh:20:3D:20n?w:20Activ?XObj?ct:28:22wscrip\"+" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}