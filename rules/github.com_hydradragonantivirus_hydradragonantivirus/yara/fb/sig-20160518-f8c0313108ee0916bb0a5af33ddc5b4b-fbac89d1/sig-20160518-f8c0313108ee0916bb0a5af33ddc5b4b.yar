rule sig_20160518_f8c0313108ee0916bb0a5af33ddc5b4b {
  meta:
    description = "datamaliciousorder - file 20160518_f8c0313108ee0916bb0a5af33ddc5b4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a97323fc54b0248848d787caec6ded5ff99725d6a085808dca1c2b45f5eb1fb4"

  strings:
    $s1  = "var sunday = [poverty, constraints,chicago,  \"\"+\".\"+(\"copyrighted\",\"travesti\",\"chrysler\",\"starch\",\"registration\"," ascii
    $s2  = "+\"SX\"+\"ML\"+(\"undertaken\",\"rural\",\"keyword\",\"sinuous\",\"hydraulic\",\"johnston\",\"conservation\",\"2.\")+\"|M\"+\"LH" ascii
    $s3  = "weasel = ((\"stronger\", \"keyboard\", \"items\", \"clearly\", \"ELhLUgIpW\") + \"aBEVEPPHDLM\").problems2();" fullword ascii
    $s4  = "var hitch=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".problems4())&&webster[\"c3RhdHVz\".problems4()] +\"\"==\"MjAw\".proble" ascii
    $s5  = "var hitch=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".problems4())&&webster[\"c3RhdHVz\".problems4()] +\"\"==\"MjAw\".proble" ascii
    $s6  = "circumstantial = \"b3Blbg==\".problems4();;" fullword ascii
    $s7  = "            webster[circumstantial]((\"healthful\",\"spoonfuls\",\"G\" + weasel) + (\"shaved\",\"corroboration\",\"chairs\",\"ex" ascii
    $s8  = "            webster[circumstantial]((\"healthful\",\"spoonfuls\",\"G\" + weasel) + (\"shaved\",\"corroboration\",\"chairs\",\"ex" ascii
    $s9  = "var fortune = sunday.pop().split(\">\");" fullword ascii
    $s10 = "String.prototype.problems4 = function() {" fullword ascii
    $s11 = "String.prototype.problems2 = function () {" fullword ascii
    $s12 = "String.prototype.problems = function () {" fullword ascii
    $s13 = "        var postcard = new amass(((\"leathery\",\"investment\",\"friends\",\"bestiality\",\"fakir\",\"outdoors\",\"unload\",\"pa" ascii
    $s14 = "        postcard[\"d3JpdGU=\".problems4()](webster[(\"documentary\",\"quibble\",\"ports\",\"woods\",\"endangered\",\"compile\"," ascii
    $s15 = "        postcard[\"d3JpdGU=\".problems4()](webster[(\"documentary\",\"quibble\",\"ports\",\"woods\",\"endangered\",\"compile\"," ascii
    $s16 = "\"T\"), banns, false);" fullword ascii
    $s17 = "var parody = prompter[sunday.shift()](sunday.shift());" fullword ascii
    $s18 = "function chains(banns, loquacious) {" fullword ascii
    $s19 = "arson = this;" fullword ascii
    $s20 = "        var postcard = new amass(((\"leathery\",\"investment\",\"friends\",\"bestiality\",\"fakir\",\"outdoors\",\"unload\",\"pa" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}