rule sig_20160315_07e2fb1944d6acf996699adec930e4f9 {
  meta:
    description = "datamaliciousorder - file 20160315_07e2fb1944d6acf996699adec930e4f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40d7687e2e27a499871df93c57436682aaafeef41b7e772e2b1f401b2de8bd5f"

  strings:
    $s1 = "function jmljvNFWjSplH(NLN){WshShell[oVQABSTeJWqKG + zkeMzwunlwoMdUD](NLN, 0, 0);}" fullword ascii
    $s2 = "while (wMRqfsrlJdPwT.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "wMRqfsrlJdPwT[HrNtkpOuBMYa + KRPXN](LwKK + uBtUfBIHbmz, rKP + CFpmRSiBsMp + JFDhyk + NVJeSNhziHjX + mpAARoVfxvEsej + lTXzk + aUu" ascii
    $s4 = "cLqfydBnSn + XcTxpkvH + CSyCCMfj + NjKvurbzu + RQUOidonsf + lQP + oUHbKSEqhF + CuF0 + WWzPWldMX + LiTxpjAMHxAgUQ, false);" fullword ascii
    $s5 = "function OcEOsFHpWS(n){return ynXoQhqDiQydxVe + RNVidTrApbBfHO + AwpqZN + bPhWMdYs + wJOAaSUgz + vGOfgZZdOVh + kpsxpufDRzihIGv;}" ascii
    $s6 = "var aCTc = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}