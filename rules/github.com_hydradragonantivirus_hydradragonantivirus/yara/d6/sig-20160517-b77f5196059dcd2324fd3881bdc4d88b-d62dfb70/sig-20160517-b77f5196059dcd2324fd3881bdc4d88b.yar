rule sig_20160517_b77f5196059dcd2324fd3881bdc4d88b {
  meta:
    description = "datamaliciousorder - file 20160517_b77f5196059dcd2324fd3881bdc4d88b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0563ffc24017001a7abdd1a7748079d9076fb4ae903cef490d6d9477bf630686"

  strings:
    $s1  = "var masturbation=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".liner4())&&incoherent[\"c3RhdHVz\".liner4()] +\"\"==\"MjAw\".li" ascii
    $s2  = "var masturbation=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".liner4())&&incoherent[\"c3RhdHVz\".liner4()] +\"\"==\"MjAw\".li" ascii
    $s3  = "adjournment = ((\"expansive\", \"shuffling\", \"wills\", \"midwest\", \"pcDrbLqUux\") + \"yhfiDrA\").liner2();" fullword ascii
    $s4  = "medicinal = medicinal+ porcelain.shift();" fullword ascii
    $s5  = "weasel = ((\"evade\", \"involved\", \"housing\", \"sophie\", \"ErMnmDl\") + \"aXMgzDcXVNE\").liner2();" fullword ascii
    $s6  = "var porcelain = [brewed, unification,trooper,  \"\"+\".\"+(\"applicant\",\"military\",\"installing\",\"blindfold\",\"valuable\"," ascii
    $s7  = "var backup = porcelain.pop().split(\"" fullword ascii
    $s8  = "String.prototype.liner = function () {" fullword ascii
    $s9  = "String.prototype.liner4 = function() {" fullword ascii
    $s10 = "String.prototype.liner2 = function () {" fullword ascii
    $s11 = "var worship = twentysixth[porcelain.shift()](porcelain.shift());" fullword ascii
    $s12 = "  playboy = [];" fullword ascii
    $s13 = "function hinting(instantly, steak) {" fullword ascii
    $s14 = "var glazed = 0;" fullword ascii
    $s15 = "var trooper =\"JVRFTVAl\".liner4();" fullword ascii
    $s16 = "horny = this;" fullword ascii
    $s17 = "    chagrin.lebanon = chagrin.inefficient[((\"inborn\",\"flashing\",\"arkansas\",\"anthropology\",\"membrane\",\"thousands\",\"f" ascii
    $s18 = "var dugout = {" fullword ascii
    $s19 = "var incoherent = new prithee(backup[0]);" fullword ascii
    $s20 = "var twentysixth = new prithee(backup[1]);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}