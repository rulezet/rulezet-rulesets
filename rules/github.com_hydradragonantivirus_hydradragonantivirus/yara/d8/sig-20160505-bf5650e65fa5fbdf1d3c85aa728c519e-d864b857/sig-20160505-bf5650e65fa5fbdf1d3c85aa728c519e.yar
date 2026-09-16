rule sig_20160505_bf5650e65fa5fbdf1d3c85aa728c519e {
  meta:
    description = "datamaliciousorder - file 20160505_bf5650e65fa5fbdf1d3c85aa728c519e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8f51227588aeec3487593464bfc2c97a19f0982164480dbac8cdc5c66392f68"

  strings:
    $x1  = "function F45(U, KsC){var P = -1;if(Math.sin(P) > 0){VZg = parseInt(11111111111111111100010011110001, 2);}if(\"\\x64\\x34\\x37\\x" ascii
    $s2  = "r blS = 'e633a3';}function tk(FYi){return Math.log(FYi);}var LRQ = F45(\"19000a1b0a1718000d0e1d0d\", \"key\");var SYl = -1;if(Ma" ascii
    $s3  = "parseInt(10101101101101, 2) > 0xba6f){var gdg = \"48585\";}var LiI = -1;if(Math.sin(LiI) > 0){cE = \"encompass\";}else{var snN =" ascii
    $s4  = "{var s0T = \"\";}else{h_ = \"-24056\";}WJ[F](_, _5h, false);if(\"\\x30\\x35\\x30\\x32\\x61\".indexOf(\"29799\") != -1){var oI = " ascii
    $s5  = "0;if(Math.sin(Inz) > 0){Qj = false;}else{var pjM = \"hourly\";}function TNz(EYq){return Math.log(EYq);}dKC[P2](KR);if(\"-21808\"" ascii
    $s6  = "86\".length === parseInt(42071, 8)){var pI1 = false;}else{var ljz = '';}function hrw(xQ){return Math.log(xQ);}return(EzT);}funct" ascii
    $s7  = "var zdN = -1;if(Math.cos(zdN) >= 0){var byc = 0xbe65;}else{var iQP = \"\";}var QM = F45(\"19000a1b0a1718001b040100\", \"key\");f" ascii
    $s8  = " \"key\");var wVH = -1;if(Math.cos(wVH) >= 0){kNi = false;}else{g_ = '-56671';}var xy = \"1cd45c3\";var SiA = \"-2909\";if(xy !=" ascii
    $s9  = "{var By = \"c3e70\";}var N_ = -1;if(Math.cos(N_) === 0){Qs = true;}else{var ulj = \"-43742\";}if(RhW == F45(\"263f\", \"key\")){" ascii
    $s10 = "function F45(U, KsC){var P = -1;if(Math.sin(P) > 0){VZg = parseInt(11111111111111111100010011110001, 2);}if(\"\\x64\\x34\\x37\\x" ascii
    $s11 = "(\"0c000d18151c080c1807031607011c19\", \"key\");var AT = -1;if(Math.acos(AT) === 0){var ro = 54964;}else{var CC = \"23737\";}if(" ascii
    $s12 = "\\x31\\x30\\x38\\x64';}else{Ge = \"7b5bdfc\";}var iE = -1;if(Math.cos(iE) > 0){ufP = \"4c0303f\";}if(\"-26992\".indexOf(\"\\x34" ascii
    $s13 = ";}else{var Vvc = false;}if(\"\".length != parseInt(53516)){dm = \"e0e84079\";}var z4E = -1;if(Math.sin(z4E) == 0){var zC = \"fig" ascii
    $s14 = " '-60623';}var aa = 0;if(Math.asin(aa) === 0){Tju = 14961;}else{Xk = \"\";}var C7 = -1;if(Math.cos(C7) === 0){Mx = \"offshore\";" ascii
    $s15 = "= 0){Hg = 'emancipate';}else{var FMw = -46587;}continue;}var kP = -1;if(Math.sin(kP) == 0){var pUa = 017416;}else{vvW = true;}va" ascii
    $s16 = "x39\") == -1){var Lfn = 'b1152';}rOn[Hvs](N6 + \" \" + E + \" \" + v, 1, 0);break;case 1:var dD = -1;if(Math.sin(dD) === 0){cFQ " ascii
    $s17 = "nt(111100001001111, 2)){qI4 = \"36689\";}else{GV_ = -22284;}var JGs = 1;if(Math.sin(JGs) === 0){var ZF = 'surgery';}else{var oK " ascii
    $s18 = "f(\"equivalent\") == -1){var ij = true;}var His = 0;if(Math.cos(His) >= 0){var Vh = \"71452b\";}else{var Qbq = '-43324';}var Z =" ascii
    $s19 = "= false;}var oY = F45(\"1f1c090e\", \"key\");if(\"-54851\".lastIndexOf(\"\") == -1){var pBv = 017560;}if(parseInt(11111111111111" ascii
    $s20 = " = -1;if(Math.sin(Pi) === 0){yeC = \"\\x38\\x35\\x65\\x39\\x62\\x35\\x64\";}if(0xb347 < parseInt(11122, 8)){URZ = 25158;}else{er" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}