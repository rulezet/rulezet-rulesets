rule sig_20160518_f3f7399512ed82a14ade00e56ba34087 {
  meta:
    description = "datamaliciousorder - file 20160518_f3f7399512ed82a14ade00e56ba34087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcdfb805fc5b1e3de644a99c45e9d7bb8e6df58d92866c6388dc7eab9fbeb2c6"

  strings:
    $s1  = "var elective = [painful, rochester,millinery,  \"\"+\".\"+(\"groove\",\"natalie\",\"demeanor\",\"relate\",\"libels\",\"castor\"," ascii
    $s2  = "var colin=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".atrocity4())&&auditor[\"c3RhdHVz\".atrocity4()] +\"\"==\"MjAw\".atroci" ascii
    $s3  = "var colin=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".atrocity4())&&auditor[\"c3RhdHVz\".atrocity4()] +\"\"==\"MjAw\".atroci" ascii
    $s4  = "weasel = ((\"offering\", \"sidon\", \"touchy\", \"accruing\", \"EDNNKlTGX\") + \"YGpHanCGE\").atrocity2();" fullword ascii
    $s5  = "for (var i in clusters){combative = combative.replace(i, clusters[i]);}" fullword ascii
    $s6  = "String.prototype.atrocity = function () {" fullword ascii
    $s7  = "String.prototype.atrocity4 = function() {" fullword ascii
    $s8  = "combative = this;" fullword ascii
    $s9  = "String.prototype.atrocity2 = function () {" fullword ascii
    $s10 = "        stretcher[(brandishing + \"o\"+(\"lounge\",\"conviction\",\"compact\",\"riverside\",\"depression\",\"jocular\",\"express" ascii
    $s11 = "        stretcher[(\"confronts\",\"zeppelin\",\"duval\",\"choke\",\"florence\",\"description\",\"syntax\",\"s\")+\"aveT\"+\"oF\"" ascii
    $s12 = "function demands(murky, purple) {" fullword ascii
    $s13 = "var millinery =\"JVendangeredRFTVendangeredAl\".atrocity4();" fullword ascii
    $s14 = "mural = \"b3Blbg==\".atrocity4();;" fullword ascii
    $s15 = "var mutable = 0;" fullword ascii
    $s16 = "var mindful = 6/6;" fullword ascii
    $s17 = ",\"blackberry\",\"apocryphal\",\"rehearsal\",\"engaging\",\"flare\",\"08\"), affront)] = 0;" fullword ascii
    $s18 = "        stretcher[(\"confronts\",\"zeppelin\",\"duval\",\"choke\",\"florence\",\"description\",\"syntax\",\"s\")+\"aveT\"+\"oF\"" ascii
    $s19 = "  elapse = [];" fullword ascii
    $s20 = "var painful = \"QWendangeredN0aXZendangeredlWE9iaendangeredmVjdA=endangered=\".atrocity4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}