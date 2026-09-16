rule sig_20160315_894664af862db39276843e40b7e8a9a9 {
  meta:
    description = "datamaliciousorder - file 20160315_894664af862db39276843e40b7e8a9a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "176a0947d949c7a02da0edc238deaa94941c6ed0016b2d05732bf48a3509a01a"

  strings:
    $s1 = "JMHhZHISwRKDoO[OQITox + bSmAXyyKX](VmubwmToOLhVYN, lBUUVJwLKLYO + KyVqovMcOGfmX + GGyEhqw + BjUd + FCTwGeTODDKGLa + VmXAIdPsPkoZ" ascii
    $s2 = "function khIIFxlnaNvh(ZJcHyqR){WshShell[DangcteAL + lxkMaTdDWBHD](ZJcHyqR, 0, 0);}" fullword ascii
    $s3 = "while (JMHhZHISwRKDoO.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s4 = "hG + pKRsTRrmKobEXBX, false);" fullword ascii
    $s5 = "function ZMZUJ(n){return Fuu + bozTuX + ZMCBH + vLfeLXqvaku + uuOFp + bsidrYZsidxN + EnZjaGwTepZ;}" fullword ascii
    $s6 = "var NlTFKKjudBbYLyk = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}