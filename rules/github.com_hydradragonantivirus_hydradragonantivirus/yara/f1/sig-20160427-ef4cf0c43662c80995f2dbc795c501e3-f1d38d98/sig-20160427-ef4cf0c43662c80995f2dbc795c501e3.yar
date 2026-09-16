rule sig_20160427_ef4cf0c43662c80995f2dbc795c501e3 {
  meta:
    description = "datamaliciousorder - file 20160427_ef4cf0c43662c80995f2dbc795c501e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07e8e55ff53f4b13ab75f198b7837368939205456680f87853892594ed80f5f9"

  strings:
    $s1  = "}switch(4) {" fullword ascii
    $s2  = "}switch(false) {" fullword ascii
    $s3  = " if(3 === true) {" fullword ascii
    $s4  = " if(4 == false) {" fullword ascii
    $s5  = "switch(3) {" fullword ascii
    $s6  = " if(3 === false) {" fullword ascii
    $s7  = " if(4 === false) {" fullword ascii
    $s8  = "}switch(0) {" fullword ascii
    $s9  = " if(2 === true) {" fullword ascii
    $s10 = " if(4 == true) {" fullword ascii
    $s11 = "}switch(6) {" fullword ascii
    $s12 = "switch(5) {" fullword ascii
    $s13 = "} if(7 == false) {" fullword ascii
    $s14 = " if(1 == false) {" fullword ascii
    $s15 = "} if(1 == true) {" fullword ascii
    $s16 = "function TsR () {" fullword ascii
    $s17 = "function tLFBk () {" fullword ascii
    $s18 = " var VyqmWI = false; " fullword ascii
    $s19 = "  var YuAYw = true; " fullword ascii
    $s20 = "function SLGBCJ (DImuMD) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}