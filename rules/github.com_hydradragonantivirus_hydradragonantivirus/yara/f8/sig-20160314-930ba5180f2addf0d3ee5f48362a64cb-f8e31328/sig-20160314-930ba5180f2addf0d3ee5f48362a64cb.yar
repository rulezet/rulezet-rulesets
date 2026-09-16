rule sig_20160314_930ba5180f2addf0d3ee5f48362a64cb {
  meta:
    description = "datamaliciousorder - file 20160314_930ba5180f2addf0d3ee5f48362a64cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce78640a44add2d4b4f36e790bde49e64b3b99b1e1168f19f6bad76b566a436e"

  strings:
    $s1 = "while (MgVK.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "return XTVuSDidP + aUmGmMpn + puycpeOjQs + LmLiygQWYIscKD + IAZ + XVrDx + sTVQV" fullword ascii
    $s3 = "MgVK.open(FCuAj + lmyeGjqW, Hgjne + KADSmLZUHfmYJ + vtteDhUJMn + vhICGII + ohJKopaCiiXuLIb + VbkDktGNYb + vCYinVv + zqkhHMEXs + " ascii
    $s4 = "function pmECGhhX(n)" fullword ascii
    $s5 = "function CdciemoM(fname)" fullword ascii
    $s6 = "nkID + fXRTzrNcRkhVPw + scrLDcpbVsM + OgoEDatcqqTmAs + izFfkT, false);" fullword ascii
    $s7 = "var mMo = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}