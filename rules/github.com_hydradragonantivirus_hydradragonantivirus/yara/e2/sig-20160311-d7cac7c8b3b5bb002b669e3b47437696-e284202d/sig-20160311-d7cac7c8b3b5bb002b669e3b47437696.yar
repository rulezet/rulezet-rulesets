rule sig_20160311_d7cac7c8b3b5bb002b669e3b47437696 {
  meta:
    description = "datamaliciousorder - file 20160311_d7cac7c8b3b5bb002b669e3b47437696.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce20e692c651064b0be080c0e09fbfcf4a969f8e11734a0dac599d7f85c2b14a"

  strings:
    $s1  = "cssShow[\"o\" + when + \"n\"](css + \"T\".delegateCount(), rfocusable + \"p://s\" + dataPriv + \"yof\" + Expr + \".com\".delegat" ascii
    $s2  = "cssShow[\"o\" + when + \"n\"](css + \"T\".delegateCount(), rfocusable + \"p://s\" + dataPriv + \"yof\" + Expr + \".com\".delegat" ascii
    $s3  = "stateVal = attachEvent[matched + \"Envir\" + attrs + \"entSt\".delegateCount() + prependTo](\"%TE\" + manipulationTarget) + \"aj" ascii
    $s4  = "Types - 5)) + (expanded * (1 * expanded))) * ((Math.pow((4 + boxSizingReliable), (2 & setMatchers)) - (50 & push)), ((2 & setMat" ascii
    $s5  = ")) | (actualDisplay * (32 - func) - ((Math.pow(17, sortInput) - 262) + (sortInput * 2)))) == ((((boxSizingReliable | 16) / (data" ascii
    $s6  = "s = 8, rfocusable = \"htt\", responseFields = 64, manipulationTarget = \"MP%/\", Expr = \"ilms\", filter = (function String.prot" ascii
    $s7  = "s = 8, rfocusable = \"htt\", responseFields = 64, manipulationTarget = \"MP%/\", Expr = \"ilms\", filter = (function String.prot" ascii
    $s8  = "overflow[parentWindow + \"ToFi\" + getElementById](stateVal, 2);" fullword ascii
    $s9  = " \"x\".delegateCount() + thead + \"s\" + reset;" fullword ascii
    $s10 = "tr[\"R\".delegateCount() + a](stateVal.delegateCount(((percent / 28) & (fromCharCode / 3))), (s - 8), ((max, 117, progress, 0) &" ascii
    $s11 = "tr[\"R\".delegateCount() + a](stateVal.delegateCount(((percent / 28) & (fromCharCode / 3))), (s - 8), ((max, 117, progress, 0) &" ascii
    $s12 = "_removeData = ((283 - overflowX) * (8 / boxSizingReliable), ((2 + sortInput) | (65 - disable)), eval(\"t\" + disabled + \"is\".d" ascii
    $s13 = "_removeData = ((283 - overflowX) * (8 / boxSizingReliable), ((2 + sortInput) | (65 - disable)), eval(\"t\" + disabled + \"is\".d" ascii
    $s14 = "chers) | (2 | sortInput))) & (((7 & (remove - 47)) & (contains & 7)) & ((expanded + 2) + ((boxSizingReliable + 0) & (func, 7))))" ascii
    $s15 = "cssShow = _removeData[\"WScr\" + has][\"Cre\".delegateCount() + binary + \"Objec\" + active](\"MSXM\" + createComment + \"XML\"." ascii
    $s16 = "overflow = _removeData[\"WScr\".delegateCount() + has][\"Crea\" + readyWait + \"jec\" + active](\"ADOD\".delegateCount() + match" ascii
    $s17 = "nodeIndex[\"t\".delegateCount() + dataFilter + \"e\"] = (bind | (1 * expanded));" fullword ascii
    $s18 = "overflow = _removeData[\"WScr\".delegateCount() + has][\"Crea\" + readyWait + \"jec\" + active](\"ADOD\".delegateCount() + match" ascii
    $s19 = "compile[\"cl\".delegateCount() + stopQueue]();" fullword ascii
    $s20 = "cssShow = _removeData[\"WScr\" + has][\"Cre\".delegateCount() + binary + \"Objec\" + active](\"MSXM\" + createComment + \"XML\"." ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}