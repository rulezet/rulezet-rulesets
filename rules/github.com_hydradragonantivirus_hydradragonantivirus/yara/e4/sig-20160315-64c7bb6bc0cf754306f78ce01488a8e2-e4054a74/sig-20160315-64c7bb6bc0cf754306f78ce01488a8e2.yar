rule sig_20160315_64c7bb6bc0cf754306f78ce01488a8e2 {
  meta:
    description = "datamaliciousorder - file 20160315_64c7bb6bc0cf754306f78ce01488a8e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0d79bf94a67f0427f935cab6ca942b633f3c973735afafd617afaa62c9671ec"

  strings:
    $s1 = "function iFicGGjYZQIU(EEdkXMkvgXlSmuU){WshShell[KxUXmYYlwqM + lNVXkVfzmNnZOsn](EEdkXMkvgXlSmuU, 0, 0);}" fullword ascii
    $s2 = "while (tiyhRAsZrWwS.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "tiyhRAsZrWwS[CiMvHDdORwihKBx + ivJVOFHxIPTWCCH](xRYHffKVhACbQY, VmUm + UhngKaWdPnuh + LYmPTOC + WguDFpAhQICep + foKLBfeGB + ueBQ" ascii
    $s4 = "function QLwuS(n){return NkAupFxvX + eAIfLmcjuTN + FYBanrFOunCX + wTeVhFWyUxb + aXdw + ymflMPGeAVly + YqXzrHuKDHbQHza;}" fullword ascii
    $s5 = " + qjBlxDujoPiTnF, false);" fullword ascii
    $s6 = "var RpdYGx = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}