rule sig_20160427_97779cac8c2b1c070e4a27345d1a2176 {
  meta:
    description = "datamaliciousorder - file 20160427_97779cac8c2b1c070e4a27345d1a2176.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36830f589e80d135c5de9620b980612f9e58de42f3b3cb415292616b6a227c82"

  strings:
    $s1  = " var FoZE = 519;FoZE = 8143 * 3885;var pLied = 3958;pLied = 4496 / 3546;var qvZ = 449;qvZ = 8619 * 1014;var kEhdjrl = 8053;kEhdj" ascii
    $s2  = " var FoZE = 519;FoZE = 8143 * 3885;var pLied = 3958;pLied = 4496 / 3546;var qvZ = 449;qvZ = 8619 * 1014;var kEhdjrl = 8053;kEhdj" ascii
    $s3  = " if(5 === true) {" fullword ascii
    $s4  = " if(1 == true) {" fullword ascii
    $s5  = "switch(0) {" fullword ascii
    $s6  = "}switch(false) {" fullword ascii
    $s7  = " if(4 == false) {" fullword ascii
    $s8  = "switch(6) {" fullword ascii
    $s9  = "switch(3) {" fullword ascii
    $s10 = "switch(false) {" fullword ascii
    $s11 = "}switch(0) {" fullword ascii
    $s12 = " if(6 == false) {" fullword ascii
    $s13 = "}switch(6) {" fullword ascii
    $s14 = "switch(5) {" fullword ascii
    $s15 = " var XSw = false; " fullword ascii
    $s16 = "function sxPLyx ( dfegg ) {" fullword ascii
    $s17 = "  var oqdtML = false; " fullword ascii
    $s18 = " var ejPMX = false; " fullword ascii
    $s19 = " if(iHIZSg === false) {" fullword ascii
    $s20 = "  var oJJxHB = true; " fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}