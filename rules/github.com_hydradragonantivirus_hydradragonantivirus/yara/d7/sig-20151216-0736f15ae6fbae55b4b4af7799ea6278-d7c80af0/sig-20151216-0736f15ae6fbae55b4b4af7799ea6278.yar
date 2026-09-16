rule sig_20151216_0736f15ae6fbae55b4b4af7799ea6278 {
  meta:
    description = "datamaliciousorder - file 20151216_0736f15ae6fbae55b4b4af7799ea6278.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0eaceda0aaa2d74d0b082b1ae6ebc9ad5f7aeaeb8388b2e1c93556de0d637613"

  strings:
    $s1  = "(Math.cos(51), 2) - 1)));} XFWmcktgv[KbOqcyxGflb]++;}KbOqcyxGflb++;} return cqyLOgCwqMS}" fullword ascii
    $s2  = "function BQOZGwwzEHbkZpXbZ(gFdrH){cqyLOgCwqMS= '';KbOqcyxGflb=Math.round((Math.pow(Math.sin(355), 2) + Math.pow(Math.cos(355), 2" ascii
    $s3  = "function BQOZGwwzEHbkZpXbZ(gFdrH){cqyLOgCwqMS= '';KbOqcyxGflb=Math.round((Math.pow(Math.sin(355), 2) + Math.pow(Math.cos(355), 2" ascii
    $s4  = "h.pow(Math.cos(606), 2) - 1)); while(true) { if(XFWmcktgv[KbOqcyxGflb] > gFdrH[KbOqcyxGflb].length-(-580+685)/105) { break; } if" ascii
    $s5  = ") - 1));while(true){if (KbOqcyxGflb >= (224+478)/117){break;}XFWmcktgv[KbOqcyxGflb]=Math.round((Math.pow(Math.sin(606), 2) + Mat" ascii
    $s6  = "function JakYvSwdVyViDdRjHBgrMiCYCOFoHerZOYAvITAhYKxBtuzDNRkzBX(GnZDVNUcVEKbL,irWhpAQeCHVwwb){ return hSsouNC[MdTteSuA[nCPmA(GnZ" ascii
    $s7  = "var E = new Array();E[0]=[];E[0][0]='d';E[0][1]='a';E[0][2]='d';E[0][3]='a';E[0][4]='46';E[0][5]='3d';E[0][6]='42';E[0][7]='14';" ascii
    $s8  = "function YRdNMPjVqUaZXRN(vsvxFKEzVJvBJVBPg,etByrhEvoRwLnChNLTsGhoHNaXXyBIStVU,ooevbdpquxBSHUmqwYeonWFowfoHFsRyvQv){eval(vsvxFKEz" ascii
    $s9  = "function nCPmA(oPdoZjaAroY,rdwIQXmlVXfBy,UTnsEFTz){MAvB=CQrvbFiqjYCVygopE(oPdoZjaAroY,rdwIQXmlVXfBy);SOTwD=MAvB.toString(UTnsEFT" ascii
    $s10 = "function V(EdvUBGNBxTzq,FZuvyQEXIKABNG){EdvUBGNBxTzq.push(FZuvyQEXIKABNG);}" fullword ascii
    $s11 = "var E = new Array();E[0]=[];E[0][0]='d';E[0][1]='a';E[0][2]='d';E[0][3]='a';E[0][4]='46';E[0][5]='3d';E[0][6]='42';E[0][7]='14';" ascii
    $s12 = "function nCPmA(oPdoZjaAroY,rdwIQXmlVXfBy,UTnsEFTz){MAvB=CQrvbFiqjYCVygopE(oPdoZjaAroY,rdwIQXmlVXfBy);SOTwD=MAvB.toString(UTnsEFT" ascii
    $s13 = "function ZAfsfJGZffu(SBJtXMVzXUTIVc) {return isNaN(SBJtXMVzXUTIVc);}" fullword ascii
    $s14 = "function JakYvSwdVyViDdRjHBgrMiCYCOFoHerZOYAvITAhYKxBtuzDNRkzBX(GnZDVNUcVEKbL,irWhpAQeCHVwwb){ return hSsouNC[MdTteSuA[nCPmA(GnZ" ascii
    $s15 = "function CQrvbFiqjYCVygopE(eKhuFrdTOD,mdOdVryvNq) {return parseInt(eKhuFrdTOD,mdOdVryvNq);}" fullword ascii
    $s16 = "function YRdNMPjVqUaZXRN(vsvxFKEzVJvBJVBPg,etByrhEvoRwLnChNLTsGhoHNaXXyBIStVU,ooevbdpquxBSHUmqwYeonWFowfoHFsRyvQv){eval(vsvxFKEz" ascii
    $s17 = "function kvKHzIisHUBw(sQBBLxHCCLeyx) {return isFinite(sQBBLxHCCLeyx);}" fullword ascii
    $s18 = "z);return SOTwD;}" fullword ascii
    $s19 = "function h(ULsRvfkBycpZtA,gazlQRHCrgRYn,ftoyTTVSago) {ULsRvfkBycpZtA[gazlQRHCrgRYn]=ftoyTTVSago;}" fullword ascii
    $s20 = "function SUmcAlg(bCCkyrwyMYlHuzMYbKhXkYcUyklQGeMrYXuU) {return !ZAfsfJGZffu(JvWZOOAFbfDdTHM(bCCkyrwyMYlHuzMYbKhXkYcUyklQGeMrYXuU" ascii

  condition:
    uint16(0) == 0x644d and
    8 of them
}