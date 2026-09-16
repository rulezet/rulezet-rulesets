rule sig_20160316_b1e8826d182a701b1401ebd4b3fcdc71 {
  meta:
    description = "datamaliciousorder - file 20160316_b1e8826d182a701b1401ebd4b3fcdc71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "866d63dded2c0045e4447ba5ee17d58d1780fded5de87d46f21f1461ef6f12c7"

  strings:
    $s1 = "while (wAxuI[tduE + VhvDZNNKZUl + ozEbEcg + ASNOhOQQurBeXXf + lVTQiTOoISQ + vPFELe + oVKLI] < 4 ) {WScript[MXYgmzYBEyk + whdtYq]" ascii
    $s2 = "while (wAxuI[tduE + VhvDZNNKZUl + ozEbEcg + ASNOhOQQurBeXXf + lVTQiTOoISQ + vPFELe + oVKLI] < 4 ) {WScript[MXYgmzYBEyk + whdtYq]" ascii
    $s3 = "function tvsz(LlSmmJPKTVTyiG){vIPU[NFGozndRV + olx](LlSmmJPKTVTyiG, 0, 0);}" fullword ascii
    $s4 = "function RXBoUaKMPnjHUZX(n){return XQphnS + WulZUkKTlytLBp + JWIXL + zALJQcBQWMLlQz + iifQZkJihhEIaCS + wxD + OsTtjd + ZcDQhr;}" fullword ascii
    $s5 = "qPyTSWjB + HJdTLloivknrt + rHr + igXP + SITjSlNwy + KICslojAJH + VYURZZHi + jtTanfDqYNjWjx, false);" fullword ascii
    $s6 = "wAxuI[HCaKwnQHg + OXQd](OvcW, QrIAz + iIv + ONanMntzlDO + wbYFB + oioCmjYBbUtuTnE + ZmM + cRD + VhtCaKngZcVRZj + NXeTQEb + HABlG" ascii
    $s7 = "var JcYWo = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}