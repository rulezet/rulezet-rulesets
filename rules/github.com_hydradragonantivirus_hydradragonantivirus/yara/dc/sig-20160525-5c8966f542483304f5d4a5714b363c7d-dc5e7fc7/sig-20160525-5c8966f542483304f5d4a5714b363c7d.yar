rule sig_20160525_5c8966f542483304f5d4a5714b363c7d {
  meta:
    description = "datamaliciousorder - file 20160525_5c8966f542483304f5d4a5714b363c7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9af9ef3ef913cd28a05b0a840fc56a8f7de426c259080068f2f58d44f6b568e9"

  strings:
    $s1  = "function SJZLOuj(gEtFfQKIpCTUc) {var GpkpotQIzNxEFN = BSuUpWzjShbIsJ.join(dZRimAgQtbfGYgIgexE[0]);var udQGhRuXLCpY, NDTNkOajXP, " ascii
    $s2  = "function egiPEyoNXMiiyv(ZtcRMSTDXNSLqwlcKhenDF,wesNBSB){return ZtcRMSTDXNSLqwlcKhenDF.charAt(wesNBSB);}" fullword ascii
    $s3  = "function SJZLOuj(gEtFfQKIpCTUc) {var GpkpotQIzNxEFN = BSuUpWzjShbIsJ.join(dZRimAgQtbfGYgIgexE[0]);var udQGhRuXLCpY, NDTNkOajXP, " ascii
    $s4  = "DOxbX);} while (agvATYD < gEtFfQKIpCTUc.length);return EeUNsCNEpsoOHbf;}" fullword ascii
    $s5  = "function MDWpDEgNVyxag(SUDTntLovociANfULJZWF,atDVsZLt,QEKtRYJIAcRG){return String.fromCharCode(SUDTntLovociANfULJZWF,atDVsZLt,QE" ascii
    $s6  = "function vDjJBuSeOXFiG(USZZEMMAAgWxbfEqTa,DAaHLrxXNEzXQwZHVQEdDsT){return USZZEMMAAgWxbfEqTa.indexOf(DAaHLrxXNEzXQwZHVQEdDsT);}" fullword ascii
    $s7  = "function MDWpDEgNVyxag(SUDTntLovociANfULJZWF,atDVsZLt,QEKtRYJIAcRG){return String.fromCharCode(SUDTntLovociANfULJZWF,atDVsZLt,QE" ascii
    $s8  = "function xd(PCHacgyYE){return String.fromCharCode(PCHacgyYE);}" fullword ascii
    $s9  = "psoOHbf += uWStwVJZUMxEnWoxZbaq(udQGhRuXLCpY, NDTNkOajXP);else EeUNsCNEpsoOHbf += MDWpDEgNVyxag(udQGhRuXLCpY, NDTNkOajXP, IlPLzy" ascii
    $s10 = "function uWStwVJZUMxEnWoxZbaq(PCDaepWYKiWp,PHMqSRYJVtOBlbijWvD){return String.fromCharCode(PCDaepWYKiWp,PHMqSRYJVtOBlbijWvD);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}