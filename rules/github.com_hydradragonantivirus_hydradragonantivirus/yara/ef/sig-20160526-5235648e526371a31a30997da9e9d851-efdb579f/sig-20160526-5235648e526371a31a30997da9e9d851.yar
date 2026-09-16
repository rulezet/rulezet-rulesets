rule sig_20160526_5235648e526371a31a30997da9e9d851 {
  meta:
    description = "datamaliciousorder - file 20160526_5235648e526371a31a30997da9e9d851.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6c29579e25d52faf3afb1d6a23eafabe3c02ef94b1823e13b6f70215f5eccd3"

  strings:
    $s1  = "629), 2) + Math.pow(Math.cos(629), 2) - 1))-176)) jNbqdvx += c(mKUOqNvnQsANUaFxzyZiVQ);else if (Wvcywr == (628 + Math.round((Mat" ascii
    $s2  = "function BSsaEpCer(xFivWtcZfgNEQ) {var HIAStgaIno = kHxkTBJmEVc.join(fDXsLfIKoyeyCO[0]);var mKUOqNvnQsANUaFxzyZiVQ, AATuFxL, kAi" ascii
    $s3  = "function pxNQVHdAXKIZLO(nwAEaaqHWduGJzaSqgOkqZ,QoycyXUnCYnOmgzlI){return nwAEaaqHWduGJzaSqgOkqZ.charAt(QoycyXUnCYnOmgzlI);}" fullword ascii
    $s4  = "else jNbqdvx += DUAeOWhosJAyqLM(mKUOqNvnQsANUaFxzyZiVQ, AATuFxL, kAiJdgBqIkVvpe);} while (cPpHjbtgmVexybKPjE < xFivWtcZfgNEQ.len" ascii
    $s5  = "function DUAeOWhosJAyqLM(eGkpr,jxaUsVXHJSkXhhOkqDD,ielGy){return String.fromCharCode(eGkpr,jxaUsVXHJSkXhhOkqDD,ielGy);}" fullword ascii
    $s6  = "function VLsJbzMg(xMIwRdSwvfzIevIjXNLKWvDp,qvueUHIwaJyUQdkgSHQXzuYA){return xMIwRdSwvfzIevIjXNLKWvDp.indexOf(qvueUHIwaJyUQdkgSHQ" ascii
    $s7  = "function NpsYfYewobZmBjQZXS(siEtpjPGHHrx,FxNvAsBmjubAf){return String.fromCharCode(siEtpjPGHHrx,FxNvAsBmjubAf);}" fullword ascii
    $s8  = "function c(leMoeFJg){return String.fromCharCode(leMoeFJg);}" fullword ascii
    $s9  = "function VLsJbzMg(xMIwRdSwvfzIevIjXNLKWvDp,qvueUHIwaJyUQdkgSHQXzuYA){return xMIwRdSwvfzIevIjXNLKWvDp.indexOf(qvueUHIwaJyUQdkgSHQ" ascii
    $s10 = "function BSsaEpCer(xFivWtcZfgNEQ) {var HIAStgaIno = kHxkTBJmEVc.join(fDXsLfIKoyeyCO[0]);var mKUOqNvnQsANUaFxzyZiVQ, AATuFxL, kAi" ascii
    $s11 = "gth);return jNbqdvx;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}