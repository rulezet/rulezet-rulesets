rule sig_20160518_25de9af073b1a5cbe1d0ec9461b1a82e {
  meta:
    description = "datamaliciousorder - file 20160518_25de9af073b1a5cbe1d0ec9461b1a82e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec1f9d5bb2e2a7af1030f1872677a1410459cbbf5cd45d2bb166e084eb729a80"

  strings:
    $s1  = "var refinance = [aggregation, antonio,entries,  \"\"+\".\"+(\"malpractice\",\"yemen\",\"lattice\",\"inflation\",\"entrap\",\"ser" ascii
    $s2  = "genealogy = \"_F2_\";" fullword ascii
    $s3  = "var sixtythree=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".technical4())&&invest[\"c3RhdHVz\".technical4()] +\"\"==\"MjAw\"." ascii
    $s4  = "var sixtythree=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".technical4())&&invest[\"c3RhdHVz\".technical4()] +\"\"==\"MjAw\"." ascii
    $s5  = "    invest[creased + (\"guatemala\",\"comedy\",\"end\")]();" fullword ascii
    $s6  = "var invest = new reparation(slovakia[0]);" fullword ascii
    $s7  = "weasel = ((\"overseer\", \"course\", \"reverting\", \"navel\", \"EsAbADPLIdQp\") + \"yFJdHVmn\").technical2();" fullword ascii
    $s8  = "  tedium = [];" fullword ascii
    $s9  = "var tentative = {" fullword ascii
    $s10 = "var disciplines = new reparation(slovakia[1]);" fullword ascii
    $s11 = "var reparation = this[refinance.shift()];" fullword ascii
    $s12 = "var refinance = [aggregation, antonio,entries,  \"\"+\".\"+(\"malpractice\",\"yemen\",\"lattice\",\"inflation\",\"entrap\",\"ser" ascii
    $s13 = "syntax(\"aHR0cDovLw==\".technical4()+\"\\u0072\\u006F\\u0074\\u0073\\u0069\\u006E\\u006F\\u006C\\u0069\\u002E\"+\"\\u0072\\u006F" ascii
    $s14 = "nce, false);" fullword ascii
    $s15 = "function syntax(mischance, shear) {" fullword ascii
    $s16 = "String.prototype.technical2 = function () {" fullword ascii
    $s17 = "String.prototype.technical4 = function() {" fullword ascii
    $s18 = "        var requirements = flows + \"/\" + shear ;" fullword ascii
    $s19 = "      tedium[ i ] = -1;" fullword ascii
    $s20 = "communism = \"b3Blbg==\".technical4();;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}