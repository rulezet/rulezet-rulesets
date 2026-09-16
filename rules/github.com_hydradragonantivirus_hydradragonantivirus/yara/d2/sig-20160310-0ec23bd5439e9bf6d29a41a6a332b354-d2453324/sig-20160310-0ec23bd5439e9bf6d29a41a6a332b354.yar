rule sig_20160310_0ec23bd5439e9bf6d29a41a6a332b354 {
  meta:
    description = "datamaliciousorder - file 20160310_0ec23bd5439e9bf6d29a41a6a332b354.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70e691b3abcfc76151b7082fe684ec2451427cf89540fb114c78375d6bcfa43d"

  strings:
    $s1  = "var Jb = true  , nWzB = Hjm[7] + Hjm[9] + Hjm[11];" fullword ascii
    $s2  = "return ipNRmuK[0] + ipNRmuK[2] + ipNRmuK[4] + \".F\" + ipNRmuK[7] + ipNRmuK[9] + ipNRmuK[12] + ipNRmuK[14];" fullword ascii
    $s3  = "var ipNRmuK = \"Sc kCWvEhW r tIEovNdbg ipting uQOjKJI BmR ile ZxPOEXLWRAdWpt System OH uOjqC Obj CjKsEj ect IEqAcZd\".split(\" " ascii
    $s4  = "var Hjm = (\"2.XMLHTTP wpKNnVt JBShm XML ream St dQHiGwVJ AD TlCqEbH O tbrH D\").split(\" \");" fullword ascii
    $s5  = "function QCmdX(Fbwjvu) {" fullword ascii
    $s6  = "LezaX.open(IeDqP,avawp,false);" fullword ascii
    $s7  = "function KWTo(xteoF) {" fullword ascii
    $s8  = "function XqvgMIUQF(QIQnM,EpQKf,aGqxs,DomW) {" fullword ascii
    $s9  = "return VpZY.ExpandEnvironmentStrings(HWRvB);" fullword ascii
    $s10 = "if (U >= NeFTn.length) {break;}" fullword ascii
    $s11 = "return Fbwjvu.position=562-562;" fullword ascii
    $s12 = "function Mnus(NeFTn) {" fullword ascii
    $s13 = "return fkSQ.responseBody;" fullword ascii
    $s14 = "if (xteoF == 602-402){return true;} else {return false;}" fullword ascii
    $s15 = "function aWkC(LezaX,avawp,IeDqP) {" fullword ascii
    $s16 = "return RfEqLQj" fullword ascii
    $s17 = "function nfPwdgzb(DWY) {" fullword ascii
    $s18 = "if(o>=g.length) {break;}" fullword ascii
    $s19 = "function rEpAdQTC() {" fullword ascii
    $s20 = "if (fzoTK > 153012-974){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}