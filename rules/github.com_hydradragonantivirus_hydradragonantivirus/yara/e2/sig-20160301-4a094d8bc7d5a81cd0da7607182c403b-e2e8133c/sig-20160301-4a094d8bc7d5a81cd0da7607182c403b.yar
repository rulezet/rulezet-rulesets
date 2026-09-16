rule sig_20160301_4a094d8bc7d5a81cd0da7607182c403b {
  meta:
    description = "datamaliciousorder - file 20160301_4a094d8bc7d5a81cd0da7607182c403b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c30a1910ce1695bd7983577fae95efa5723f778232aef28b0c22bbd1911d4b1c"

  strings:
    $s1 = "while(collectiveDialogue[(\"\\u0070r\\u0065\\u0063\" + \"\\u0069\" + \"\\u0073ion\", \"sym\" + \"\\u006de\\u0074\\u0072\" + \"" ascii
    $s2 = "while(collectiveDialogue[(\"\\u0070r\\u0065\\u0063\" + \"\\u0069\" + \"\\u0073ion\", \"sym\" + \"\\u006de\\u0074\\u0072\" + \"" ascii
    $s3 = "mechanicMedicine = (((644 / 23) - (16 ^ 11)), this);" fullword ascii
    $s4 = "   registryPortal[(\"s\\u0068\\u006fr\\u0074s\", function String.prototype.tractInternational() {" fullword ascii
    $s5 = "} catch(numerationTransform) {};" fullword ascii

  condition:
    uint16(0) == 0x656d and
    all of them
}