rule sig_20160301_765e18d48c57312ed082fd913d012a79 {
  meta:
    description = "datamaliciousorder - file 20160301_765e18d48c57312ed082fd913d012a79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4265240097d31e74dedff0b0f37b79316cbd394a1814b81e7c61c0830cf149d9"

  strings:
    $s1 = "while(distantCulture[(\"se\\u0072io\" + \"u\\u0073\", \"\\u0063oll\\u0069\" + \"\\u0073\\u0069\\u006fn\", \"\\u0072\\u0065a\" + " ascii
    $s2 = "while(distantCulture[(\"se\\u0072io\" + \"u\\u0073\", \"\\u0063oll\\u0069\" + \"\\u0073\\u0069\\u006fn\", \"\\u0072\\u0065a\" + " ascii
    $s3 = "recipeScalpel = variantApparatus[(\"axiom\", \"\\u0073oci\" + \"a\\u006c\", function String.prototype.delegationSalute() {" fullword ascii
    $s4 = "violetAccordion = (((23 / 23) ^ (0)), this);" fullword ascii
    $s5 = "} catch(machineRecord) {};" fullword ascii

  condition:
    uint16(0) == 0x6976 and
    all of them
}