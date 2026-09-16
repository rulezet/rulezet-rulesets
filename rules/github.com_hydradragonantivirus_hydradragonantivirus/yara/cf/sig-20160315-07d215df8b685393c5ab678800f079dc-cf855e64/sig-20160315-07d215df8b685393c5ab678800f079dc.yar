rule sig_20160315_07d215df8b685393c5ab678800f079dc {
  meta:
    description = "datamaliciousorder - file 20160315_07d215df8b685393c5ab678800f079dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c9ecf7436d38f8f80d33569735293637eb727277b50001f7d0577c024fbb893"

  strings:
    $s1 = "function fZBOR(WfHLpqXQcsTXQ){WshShell[pizJ + OnFBPAa](WfHLpqXQcsTXQ, 0, 0);}" fullword ascii
    $s2 = "mWqrcxExD[exTYHpabu + fnOEbOpRQu](okUfsbHh + tIIfmjNiV, gJuqDnWWxzj + IXo + uhlwW + GcOMaoTr + JkECL + XDgvVbjVSgud + SpjJfunvX " ascii
    $s3 = "while (mWqrcxExD.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s4 = " + GqLXEkucpx + BSCM, false);" fullword ascii
    $s5 = "function THIrEneePHZBcqP(n){return oClZsK + jXCrdL + kCJcARfFLIICM + DdbKhgLZRAAKPj + fEtIEGMVLxRv + cNSrtCoW + IOlvuzgkSS;}" fullword ascii
    $s6 = "var CgiHVPc = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}