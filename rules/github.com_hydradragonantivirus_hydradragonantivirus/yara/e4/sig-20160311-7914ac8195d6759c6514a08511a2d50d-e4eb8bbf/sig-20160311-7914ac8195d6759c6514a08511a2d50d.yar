rule sig_20160311_7914ac8195d6759c6514a08511a2d50d {
  meta:
    description = "datamaliciousorder - file 20160311_7914ac8195d6759c6514a08511a2d50d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51c014e5b38dcf2ace60568bf6776082648a5903594a7f9cd379686728e45614"

  strings:
    $s1  = "var eO = true  , xbqz = TQY[7] + TQY[9] + TQY[11];" fullword ascii
    $s2  = "return MMXtKbc[0] + MMXtKbc[2] + MMXtKbc[4] + \".F\" + MMXtKbc[7] + MMXtKbc[9] + MMXtKbc[12] + MMXtKbc[14];" fullword ascii
    $s3  = "IjkiG.open(VJwmf,CrqLc,false);" fullword ascii
    $s4  = "var TQY = (\"2.XMLHTTP kKMtWCr UsoeI XML ream St iYelNcGq AD jJOzshX O pOdP D\").split(\" \");" fullword ascii
    $s5  = "var MMXtKbc = \"Sc yuAwELX r yCzIJDeJb ipting kwbnrXR DUD ile CpELQfNPGdUPff System RQ BcmWs Obj cewlkn ect DgvKdRu\".split(\" " ascii
    $s6  = "return SShdx.status;" fullword ascii
    $s7  = "function bPVI(MZPyr,NSGAY) {" fullword ascii
    $s8  = "function KYqg(CddvG) {" fullword ascii
    $s9  = "return new ActiveXObject(XkJmPh);" fullword ascii
    $s10 = "return QBB.size;" fullword ascii
    $s11 = "if (zUdDg > 140140-146){return true;} else {return false;}" fullword ascii
    $s12 = "function yTeD(bVcjZ,RwSwn) {" fullword ascii
    $s13 = "function jTfOhZXb(UvVOc,ltsxLI) {" fullword ascii
    $s14 = "return NRJCBRV" fullword ascii
    $s15 = "return MxXFFJL(LH,snKUy[219-213]+snKUy[987-980]+snKUy[589-581]);" fullword ascii
    $s16 = "return NdKAbM.position=380-380;" fullword ascii
    $s17 = "if(x>=y.length) {break;}" fullword ascii
    $s18 = "function VbYKisUYW(kpspwgpQmtj) {" fullword ascii
    $s19 = "function aFMz(MmjKr) {" fullword ascii
    $s20 = "return mtne.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}