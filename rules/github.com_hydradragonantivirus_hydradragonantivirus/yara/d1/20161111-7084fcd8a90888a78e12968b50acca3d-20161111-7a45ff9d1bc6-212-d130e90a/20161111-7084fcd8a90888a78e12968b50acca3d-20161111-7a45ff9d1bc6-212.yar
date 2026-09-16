rule _20161111_7084fcd8a90888a78e12968b50acca3d_20161111_7a45ff9d1bc6_212 {
  meta:
    description = "datamaliciousorder - from files 20161111_7084fcd8a90888a78e12968b50acca3d.js, 20161111_7a45ff9d1bc682539437ba1ba50da7e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4dd203720b7d095bd4b85f74f23234839a90b57a85229d4f4cb17e3a06f1236"
    hash2       = "7cf8c610cbf605f126d8a5008daf3345c9fb1c312abaaa29e6d41aea6c0fa4ed"

  strings:
    $s1  = "var GEOMETRIA500 = new Function(\"arahisoviybutchersFROG2_a5,arahisoviybutchersFROG2HORDA5\", 'return arahisoviybutchersFROG2_bC" ascii
    $s2  = "arahisoviybutchersFROG2undefilled.angle = function(arahisoviybutchersFROG2p) {" fullword ascii
    $s3  = "arahisoviybutchersFROG2Native.arahisoviybutchersFROG2typize=function(a,b){a.type||(a.type=function(a){return arahisoviybutchersF" ascii
    $s4  = "arahisoviybutchersFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s5  = "arahisoviybutchersFROG2undefilled.arahisoviybutchersFROG2sameOrN = function(arahisoviybutchersFROG2param1, arahisoviybutchersFRO" ascii
    $s6  = "arahisoviybutchersFROG2undefilled.arahisoviybutchersFROG2sameOrN = function(arahisoviybutchersFROG2param1, arahisoviybutchersFRO" ascii
    $s7  = "arahisoviybutchersFROG2Native.arahisoviybutchersFROG2typize=function(a,b){a.type||(a.type=function(a){return arahisoviybutchersF" ascii
    $s8  = "        } while (arahisoviybutchersFROG2XCOP < arahisoviybutchersFROG2len && arahisoviybutchersFROG2ddDccC1 == -1);" fullword ascii
    $s9  = "        } while (arahisoviybutchersFROG2XCOP < arahisoviybutchersFROG2len && arahisoviybutchersFROG2ddDccC2 == -1);" fullword ascii
    $s10 = "        } while (arahisoviybutchersFROG2XCOP < arahisoviybutchersFROG2len && arahisoviybutchersFROG2c4 == -1);" fullword ascii
    $s11 = "        } while (arahisoviybutchersFROG2XCOP < arahisoviybutchersFROG2len && arahisoviybutchersFROG2c3 == -1);" fullword ascii
    $s12 = "if (arahisoviybutchersFROG2FrankSinatra[0]!= 77 || arahisoviybutchersFROG2FrankSinatra[1]!= 90)return false;" fullword ascii
    $s13 = "function arahisoviybutchersFROG2_aCho(T, D) {" fullword ascii
    $s14 = "};arahisoviybutchersFROG2Native.arahisoviybutchersFROG2XCOPmplement = function(arahisoviybutchersFROG2objects, arahisoviybutcher" ascii
    $s15 = "function arahisoviybutchersFROG2_cCho(a,b,c,d){a[b](c,d)}" fullword ascii
    $s16 = "var arahisoviybutchersFROG2Native = function(options){" fullword ascii
    $s17 = "function arahisoviybutchersFROG2_a2(arahisoviybutchersFROG2gutter, arahisoviybutchersFROG2StrokaParam2) {" fullword ascii
    $s18 = "function arahisoviybutchersFROG2undefilled(velVLUMAHx, velVLUMAHy) {" fullword ascii
    $s19 = "function arahisoviybutchersFROG2sud(vardos){" fullword ascii
    $s20 = "var GEOMETRIA500 = new Function(\"arahisoviybutchersFROG2_a5,arahisoviybutchersFROG2HORDA5\", 'return arahisoviybutchersFROG2_bC" ascii

  condition:
    (uint16(0) == 0x7620 and (8 of them)
    ) or (all of them)
}