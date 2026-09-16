rule _20161111_8895c12b026e9df1bf6337891d69e584_20161111_896dcc2eddba_202 {
  meta:
    description = "datamaliciousorder - from files 20161111_8895c12b026e9df1bf6337891d69e584.js, 20161111_896dcc2eddba6151067f713cf0d12b4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6b5f977805303faa6215cd4e011857a46a5557d8ff5485611d09080ed4fc490"
    hash2       = "9aeef1eb44f0fdc29904c367827d94067033db71091ccddf3a2d93a259b22ec0"

  strings:
    $s1  = "var GEOMETRIA500 = new Function(\"arahisoviyforthcomingFROG2_a5,arahisoviyforthcomingFROG2HORDA5\", 'return arahisoviyforthcomin" ascii
    $s2  = "arahisoviyforthcomingFROG2undefilled.arahisoviyforthcomingFROG2sameOrN = function(arahisoviyforthcomingFROG2param1, arahisoviyfo" ascii
    $s3  = "arahisoviyforthcomingFROG2Native.arahisoviyforthcomingFROG2typize=function(a,b){a.type||(a.type=function(a){return arahisoviyfor" ascii
    $s4  = "arahisoviyforthcomingFROG2Native.arahisoviyforthcomingFROG2typize=function(a,b){a.type||(a.type=function(a){return arahisoviyfor" ascii
    $s5  = "arahisoviyforthcomingFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s6  = "arahisoviyforthcomingFROG2undefilled.arahisoviyforthcomingFROG2sameOrN = function(arahisoviyforthcomingFROG2param1, arahisoviyfo" ascii
    $s7  = "arahisoviyforthcomingFROG2undefilled.angle = function(arahisoviyforthcomingFROG2p) {" fullword ascii
    $s8  = "        } while (arahisoviyforthcomingFROG2XCOP < arahisoviyforthcomingFROG2len && arahisoviyforthcomingFROG2ddDccC2 == -1);" fullword ascii
    $s9  = "        } while (arahisoviyforthcomingFROG2XCOP < arahisoviyforthcomingFROG2len && arahisoviyforthcomingFROG2c3 == -1);" fullword ascii
    $s10 = "        } while (arahisoviyforthcomingFROG2XCOP < arahisoviyforthcomingFROG2len && arahisoviyforthcomingFROG2ddDccC1 == -1);" fullword ascii
    $s11 = "        } while (arahisoviyforthcomingFROG2XCOP < arahisoviyforthcomingFROG2len && arahisoviyforthcomingFROG2c4 == -1);" fullword ascii
    $s12 = "function arahisoviyforthcomingFROG2_bCho(T, D, C) {" fullword ascii
    $s13 = "function arahisoviyforthcomingFROG2_a2(arahisoviyforthcomingFROG2gutter, arahisoviyforthcomingFROG2StrokaParam2) {" fullword ascii
    $s14 = "if(arahisoviyforthcomingFROG2FrankSinatraLaa < 29989)return false;" fullword ascii
    $s15 = "function arahisoviyforthcomingFROG2sud(vardos){" fullword ascii
    $s16 = "};arahisoviyforthcomingFROG2Native.arahisoviyforthcomingFROG2XCOPmplement = function(arahisoviyforthcomingFROG2objects, arahisov" ascii
    $s17 = "function arahisoviyforthcomingFROG2_aCho(T, D) {" fullword ascii
    $s18 = "function arahisoviyforthcomingFROG2undefilled(velVLUMAHx, velVLUMAHy) {" fullword ascii
    $s19 = "if (arahisoviyforthcomingFROG2FrankSinatra[0]!= 77 || arahisoviyforthcomingFROG2FrankSinatra[1]!= 90)return false;" fullword ascii
    $s20 = "arahisoviyforthcomingFROG2rampart[arahisoviyforthcomingFROG2promises ]((arahisoviyforthcomingFROG2StrokaParam2,\"r\") +arahisovi" ascii

  condition:
    (uint16(0) == 0x7620 and (8 of them)
    ) or (all of them)
}