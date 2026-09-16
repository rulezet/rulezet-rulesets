rule sig_20160507_c6f9e5bc8d5d9200e1227737380f5732 {
  meta:
    description = "datamaliciousorder - file 20160507_c6f9e5bc8d5d9200e1227737380f5732.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e0d7a230532a50caa06a6a349f11948c58b8cb542e8d27f5e85b5822d6d6ff2"

  strings:
    $x1  = "function Bv(KDX, f){if(\"\\x31\\x38\\x62\\x31\\x36\".lastIndexOf(\"16861\") > 0){ltL = parseInt(-33447);}else{Tq = \"\\x64\\x35" ascii
    $s2  = "(SOc) == 0){var MS = 0xffff5369;}for(W5o = 0; W5o < jVH.length; W5o++){try{function LRQ(KR){return Math.log(KR);}if(026211 <= -3" ascii
    $s3  = "S = \"4fc9669\";}var pSg = nK + \"\\\\\" + V + \".\" + nz;function tld(FMZ){return Math.log(FMZ);}function HG(Yhq){return Math.l" ascii
    $s4  = "cT(UE){return Math.log(UE);}var gmM = 1;if(Math.acos(gmM) === 0){var wCp = 0x7250;}if(\"\\x35\\x38\\x61\\x30\".lastIndexOf(\"-29" ascii
    $s5  = "52);}if(037736 <= 037777732443){aF = true;}else{var Pzr = \"get\";}var eW = -1;if(Math.sin(eW) >= 0){_z = false;}else{var dU = " ascii
    $s6  = "943;}else{var ynv = \"\";}fQp = fQp + 1;if(\"c7f409\".indexOf(\"\\x65\\x63\\x63\\x62\\x63\\x37\\x63\\x64\") == -1){wq = -9783;}e" ascii
    $s7  = "ar _o = \"-4658\";}return(z);}function RQ(a){var ThN = 1;if(Math.asin(ThN) > 0){ZG = -37752;}var lGn = -1;if(Math.sin(lGn) === 0" ascii
    $s8  = "= 0xffff7356;}var TK = -1;if(Math.asin(TK) > 0){AG = '\\x64\\x31\\x33\\x31';}else{yE = \"-12208\";}function Kr(Mpo){return Math." ascii
    $s9  = "Math.atan2(ym6, Dz);}if(\"44701\".indexOf(\"-38192\") == 0){Ron = \"\";}else{tg = 43828;}if(\"leonard\".lastIndexOf(\"pessimisti" ascii
    $s10 = "f(Math.sin(O) > 0){var A = false;}else{var juK = -60861;}var KM = 0;if(Math.cos(KM) >= 0){JCQ = \"\";}var j = JWN(KDX);if(\"5352" ascii
    $s11 = " clb){var yD = false;}else{J8 = false;}var on = 0;if(Math.cos(on) > 0){C4 = \"122b\";}if(\"davis\".indexOf(\"-34302\") != -1){BV" ascii
    $s12 = ";}if(\"32270\".length > 23660){var s6V = 064655;}var ivq = -1;if(Math.cos(ivq) != 0){Pfj = parseInt(63588);}else{hCc = \"daddy\"" ascii
    $s13 = ");var AY = -1;if(Math.cos(AY) >= 0){lvl = \"64264\";}else{Kz = 0xffffc005;}var oUm = -1;if(Math.cos(oUm) == 0){C1n = 11731;}var " ascii
    $s14 = "r = -1;if(Math.cos(tr) === 0){var Zm = '11504';}if(\"e1878879\".length == -10287){fq = 0150754;}else{cMw = 'clubs';}if(\"\\x37" ascii
    $s15 = "ally{var dcl = parseInt(-22730);}function xzl(Hq_){return Math.exp(Hq_);}if(\"-47362\".indexOf(\"c6bfb\") != -1){var v1d = \"65c" ascii
    $s16 = "382e591d1120155131\", \"Bz5HA7nt\");var NR = -1;if(Math.sin(NR) != 0){vWC = \"\";}else{var zz = '\\x61\\x62\\x37\\x31\\x32\\x30" ascii
    $s17 = "36\\x38\\x62\\x30\\x33\".lastIndexOf(\"\") == -1){vo_ = 'cc882a';}function Fu(hOh){return Math.round(hOh);}var Jc = 1;if(Math.co" ascii
    $s18 = " != -1){var YR = \"preamble\";}else{jg = \"90f0\";}var nDL = -1;if(Math.sin(nDL) == 0){has = \"\";}else{iTk = parseInt(-34298);}" ascii
    $s19 = "){return Math.atan(kUF);}function eZs(J1){return Math.exp(J1);}if(\"24188\".length > -30932){AQZ = parseInt(36772);}var Axt = \"" ascii
    $s20 = "G = 1;if(Math.cos(iZG) > 0){var mq = -44552;}var nn = -1;if(Math.sin(nn) === 0){var NEX = false;}else{var AA = '1d7f7d';}var V =" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}