rule sig_20160314_6ff996a2f5286c731acaa98b8c0d8977 {
  meta:
    description = "datamaliciousorder - file 20160314_6ff996a2f5286c731acaa98b8c0d8977.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67a1aac96724db9b094265ec8a85512adfa4a07819be235e0a4a22625e5774b0"

  strings:
    $s1  = "var tn = true  , Agst = LmO[7] + LmO[9] + LmO[11];" fullword ascii
    $s2  = "return HYzMlQB[0] + HYzMlQB[2] + HYzMlQB[4] + \".F\" + HYzMlQB[7] + HYzMlQB[9] + HYzMlQB[12] + HYzMlQB[14];" fullword ascii
    $s3  = "fSGuV.open(pXCZI,WtArD,false);" fullword ascii
    $s4  = "var LmO = (\"2.XMLHTTP utXWuJV hvmXp XML ream St VdibeuvS AD lOMTmFk O ztvl D\").split(\" \");" fullword ascii
    $s5  = "var HYzMlQB = \"Sc sLNeVdU r vQIOooqbi ipting reCuyRh Vjs ile nJjogVJRSsOyLc System hf oJlEu Obj bVNZzi ect LwsyUBD okZWU\".spli" ascii
    $s6  = "var HYzMlQB = \"Sc sLNeVdU r vQIOooqbi ipting reCuyRh Vjs ile nJjogVJRSsOyLc System hf oJlEu Obj bVNZzi ect LwsyUBD okZWU\".spli" ascii
    $s7  = "if(d>=u.length) {break;}" fullword ascii
    $s8  = "function paYu(SbhvF) {" fullword ascii
    $s9  = "if (jBlIq > 197294-603){return true;} else {return false;}" fullword ascii
    $s10 = "function UiaG(BoPlM) {" fullword ascii
    $s11 = "return FsBi.ExpandEnvironmentStrings(NfAQc);" fullword ascii
    $s12 = "return Zihi.responseBody;" fullword ascii
    $s13 = "function coxD(QjLbd) {" fullword ascii
    $s14 = "function VqneDZB(FsBi,NfAQc) {" fullword ascii
    $s15 = "mHa = d; break; " fullword ascii
    $s16 = "function StxRVsGDo() {" fullword ascii
    $s17 = "function QUSQ(jBlIq) {" fullword ascii
    $s18 = "function CPxk(BjEVc,ArnzP) {" fullword ascii
    $s19 = "return tUlON.status;" fullword ascii
    $s20 = "return bPPABBC" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}