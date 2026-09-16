rule sig_20160516_7b452a0ebf0b39c7ad7494acd7dbe8be {
  meta:
    description = "datamaliciousorder - file 20160516_7b452a0ebf0b39c7ad7494acd7dbe8be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "637fe92a2e14f13ac08562376c1b81f13ff14c22b6e7b02cd0637ac893009643"

  strings:
    $s1  = "var thicken = [peanuts, pennies,epirus,  \"\"+\".\"+(\"artificers\",\"motherinlaw\",\"homestead\",\"pontiff\",\"netherlands\",\"" ascii
    $s2  = "        var jargon = new telecommunications(((\"demagogue\",\"proud\",\"bonds\",\"freehold\",\"applicants\",\"admin\",\"magnanim" ascii
    $s3  = "function joined(farfetched, physiology) {" fullword ascii
    $s4  = "+(\"fertilizing\",\"peking\",\"analogies\",\"continent\",\"secured\",\"vicissitude\",\"conservative\",\"2.\")+\"XM\"+\"LH\"+\"TT" ascii
    $s5  = "rated = ((\"diverge\", \"farming\", \"traditionally\", \"pertinent\", \"sQEdKCBMh\") + \"mOxDWf\").reprobate2();" fullword ascii
    $s6  = "weasel = ((\"pichunter\", \"abuse\", \"grande\", \"apoplectic\", \"EMSmABandh\") + \"edFMiof\").reprobate2();" fullword ascii
    $s7  = "String.prototype.reprobate2 = function () {" fullword ascii
    $s8  = "var forage = thicken.pop().split(\"" fullword ascii
    $s9  = "String.prototype.reprobate = function () {" fullword ascii
    $s10 = "String.prototype.reprobate4 = function() {" fullword ascii
    $s11 = "    citizens[rated + (\"surprising\",\"proportional\",\"end\")]();" fullword ascii
    $s12 = "ger\",\"loftiness\",\"warnings\",\"chaplet\",\"house\",\"logging\",\"\")+\"R\"+\"es\"+\"pon\"+birthday['U'].toLowerCase()+\"e\"+" ascii
    $s13 = "ited\",\"fishy\",\"evaluation\",\"vertigo\",\"poignant\",\"08\"), rated)] = 0;" fullword ascii
    $s14 = "var thicken = [peanuts, pennies,epirus,  \"\"+\".\"+(\"artificers\",\"motherinlaw\",\"homestead\",\"pontiff\",\"netherlands\",\"" ascii
    $s15 = "var prithee = 0;" fullword ascii
    $s16 = "produced = \"_F2_\";" fullword ascii
    $s17 = "var personally = 6/6;" fullword ascii
    $s18 = "var birthday = {" fullword ascii
    $s19 = "ed, false);" fullword ascii
    $s20 = "disability = \"b3Blbg==\".reprobate4();;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}