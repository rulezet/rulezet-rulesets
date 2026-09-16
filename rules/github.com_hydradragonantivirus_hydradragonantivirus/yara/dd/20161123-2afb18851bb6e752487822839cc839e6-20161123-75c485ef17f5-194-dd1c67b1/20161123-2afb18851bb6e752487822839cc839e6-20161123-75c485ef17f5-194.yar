rule _20161123_2afb18851bb6e752487822839cc839e6_20161123_75c485ef17f5_194 {
  meta:
    description = "datamaliciousorder - from files 20161123_2afb18851bb6e752487822839cc839e6.js, 20161123_75c485ef17f5850731db518a6ef3ded2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f6dbde31dd9bd8491e8f3be250e3ac55584ffb8cded4398662890b7018d8922"
    hash2       = "12f7c00d3c522b4a1526e3f0878fdddd069c804b4d20987460bb1a185228e4b4"

  strings:
    $s1  = " var POLKAOLKA500 = new Function(\"ChickagoMasterprovenderFROG2_a5,ChickagoMasterprovenderFROG2HORDA5\", 'return ChickagoMasterp" ascii
    $s2  = "ChickagoMasterprovenderFROG2undefilled.ChickagoMasterprovenderFROG2sameOrN = function(ChickagoMasterprovenderFROG2param1, Chicka" ascii
    $s3  = "ChickagoMasterprovenderFROG2Native.ChickagoMasterprovenderFROG2XCOPmplement = function(ChickagoMasterprovenderFROG2objects, Chic" ascii
    $s4  = "ChickagoMasterprovenderFROG2undefilled.ChickagoMasterprovenderFROG2sameOrN = function(ChickagoMasterprovenderFROG2param1, Chicka" ascii
    $s5  = "ChickagoMasterprovenderFROG2Native.ChickagoMasterprovenderFROG2XCOPmplement = function(ChickagoMasterprovenderFROG2objects, Chic" ascii
    $s6  = "ChickagoMasterprovenderFROG2undefilled.angle = function(ChickagoMasterprovenderFROG2p) {" fullword ascii
    $s7  = "ChickagoMasterprovenderFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s8  = "        } while (ChickagoMasterprovenderFROG2XCOP < ChickagoMasterprovenderFROG2len && ChickagoMasterprovenderFROG2ddDccC2 == -1" ascii
    $s9  = "        } while (ChickagoMasterprovenderFROG2XCOP < ChickagoMasterprovenderFROG2len && ChickagoMasterprovenderFROG2ddDccC2 == -1" ascii
    $s10 = "        } while (ChickagoMasterprovenderFROG2XCOP < ChickagoMasterprovenderFROG2len && ChickagoMasterprovenderFROG2ddDccC1 == -1" ascii
    $s11 = "        } while (ChickagoMasterprovenderFROG2XCOP < ChickagoMasterprovenderFROG2len && ChickagoMasterprovenderFROG2c3 == -1);" fullword ascii
    $s12 = "        } while (ChickagoMasterprovenderFROG2XCOP < ChickagoMasterprovenderFROG2len && ChickagoMasterprovenderFROG2c4 == -1);" fullword ascii
    $s13 = "        } while (ChickagoMasterprovenderFROG2XCOP < ChickagoMasterprovenderFROG2len && ChickagoMasterprovenderFROG2ddDccC1 == -1" ascii
    $s14 = "function  ChickagoMasterprovenderFROG2_bCho(T, D, C) {" fullword ascii
    $s15 = " var ChickagoMasterprovenderFROG2Native = function(options){" fullword ascii
    $s16 = "if(ChickagoMasterprovenderFROG2FrankSinatraLaa < 29989)return false;" fullword ascii
    $s17 = "function  ChickagoMasterprovenderFROG2undefilled(velVLUMAHx, velVLUMAHy) {" fullword ascii
    $s18 = "function  ChickagoMasterprovenderFROG2sud(vardos){" fullword ascii
    $s19 = "for ( var ChickagoMasterprovenderFROG2XCOP = 0, ChickagoMasterprovenderFROG2l = ChickagoMasterprovenderFROG2objects.length; Chic" ascii
    $s20 = "function  ChickagoMasterprovenderFROG2_a2(ChickagoMasterprovenderFROG2gutter, ChickagoMasterprovenderFROG2StrokaParam2) {" fullword ascii

  condition:
    (uint16(0) == 0x0d20 and (8 of them)
    ) or (all of them)
}