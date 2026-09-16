rule sig_20160315_22184d81f3eda31f18a1cdd70fe949df {
  meta:
    description = "datamaliciousorder - file 20160315_22184d81f3eda31f18a1cdd70fe949df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83d65c622356d090fbc05a854f31ab7ce1bc42af6090579e696b7661f01f8062"

  strings:
    $s1 = "function QUqHD(deItqGYSvtk){WshShell[nhoT + SDuoufGB](deItqGYSvtk, 0, 0);}" fullword ascii
    $s2 = "while (KuuenwY.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "FHd + qrZvoD + mBHqNnsmAfnjUZU, false);" fullword ascii
    $s4 = "function SJnNoJsbQ(n){return VnEUSFh + oWCqWcGPPjnv + mPzjWBjL + kis + CsUUVxsVa + bkIMUmL;}" fullword ascii
    $s5 = "KuuenwY[BLRvruGFIhY + VmEQwzFhJMFRR](zZsgivklTB + WSuKUYQNPOK + lXMtZLSYsBkduBN, DjlY + JiEAVH + eJzqyeYZ + PLXYmqwZCtoGO + ezfT" ascii
    $s6 = "var ERiTeQjvseAHo = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}