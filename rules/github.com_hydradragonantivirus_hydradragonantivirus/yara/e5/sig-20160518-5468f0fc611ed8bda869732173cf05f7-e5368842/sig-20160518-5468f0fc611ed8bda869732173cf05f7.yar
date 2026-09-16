rule sig_20160518_5468f0fc611ed8bda869732173cf05f7 {
  meta:
    description = "datamaliciousorder - file 20160518_5468f0fc611ed8bda869732173cf05f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9c4ae64eb4a01f760349a392528d7c0866e92b1f7c8b8f7ec3f5f86a192a0f8"

  strings:
    $x1  = "var decimal = [attempt, objecting,hamlet,  \"\"+\".\"+(\"carrot\",\"elvis\",\"chase\",\"moved\",\"norwegian\",\"pointed\",\"spec" ascii
    $s2  = "var attempt = \"QWsaturatedN0aXZsaturatedlWE9iasaturatedmVjdA=saturated=\".guarantee4();" fullword ascii
    $s3  = "var devastation=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".guarantee4())&&strongly[\"c3RhdHVz\".guarantee4()] +\"\"==\"MjAw" ascii
    $s4  = "var devastation=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".guarantee4())&&strongly[\"c3RhdHVz\".guarantee4()] +\"\"==\"MjAw" ascii
    $s5  = "+(\"interposition\",\"handicapped\",\"vulnerable\",\"toothed\",\"lustful\",\"bulky\",\"batting\",\"2.\")+\"|M\"+\"LH\"+\"TT\"+(" ascii
    $s6  = "seduction = ((\"feldspar\", \"priority\", \"cohen\", \"organize\", \"sHdbxvDHcnnf\") + \"oQfFHwqfe\").guarantee2();" fullword ascii
    $s7  = "duality = duality+ decimal.shift();" fullword ascii
    $s8  = "weasel = ((\"constraint\", \"afire\", \"detention\", \"conflagration\", \"ExAyxRqxzEXp\") + \"OTspozwDrS\").guarantee2();" fullword ascii
    $s9  = "smoker = ((\"communal\", \"castaway\", \"disruption\", \"sunset\", \"pxuolBRzAO\") + \"CzFoElGLfT\").guarantee2();" fullword ascii
    $s10 = "\"passerby\",\"property\",\"visual\",\"obituary\",\"08\"), seduction)] = 0;" fullword ascii
    $s11 = "String.prototype.guarantee4 = function() {" fullword ascii
    $s12 = "var decimal = [attempt, objecting,hamlet,  \"\"+\".\"+(\"carrot\",\"elvis\",\"chase\",\"moved\",\"norwegian\",\"pointed\",\"spec" ascii
    $s13 = "String.prototype.guarantee2 = function () {" fullword ascii
    $s14 = "String.prototype.guarantee = function () {" fullword ascii
    $s15 = "var curriculum = decimal.pop().split(\">\");" fullword ascii
    $s16 = "        resident[(smoker + \"o\"+(\"limbo\",\"tiller\",\"bookings\",\"madness\",\"mailto\",\"allurement\",\"strap\",\"bound\",\"" ascii
    $s17 = "        resident[(smoker + \"o\"+(\"limbo\",\"tiller\",\"bookings\",\"madness\",\"mailto\",\"allurement\",\"strap\",\"bound\",\"" ascii
    $s18 = "var hamlet =\"JVsaturatedRFTVsaturatedAl\".guarantee4();" fullword ascii
    $s19 = "volkswagen = this;" fullword ascii
    $s20 = "for (var i in lassitude){volkswagen = volkswagen.replace(i, lassitude[i]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}