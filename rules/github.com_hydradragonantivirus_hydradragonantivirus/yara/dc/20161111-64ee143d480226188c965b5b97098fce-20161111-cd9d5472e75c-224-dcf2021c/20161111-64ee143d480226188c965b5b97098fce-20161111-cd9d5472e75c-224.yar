rule _20161111_64ee143d480226188c965b5b97098fce_20161111_cd9d5472e75c_224 {
  meta:
    description = "datamaliciousorder - from files 20161111_64ee143d480226188c965b5b97098fce.js, 20161111_cd9d5472e75cf6646b5119077ae92623.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7070b58a7c9f212ee969122f51b95220afc466a7e0b5ebe4eee577a42565a1f1"
    hash2       = "7add02bd64695eb3d1c34399683392a61365e400b585e54b65e85ed3b43ab8cf"

  strings:
    $s1  = "var GEOMETRIA500 = new Function(\"cvetnoybulgrannieFROG2_a5,cvetnoybulgrannieFROG2HORDA5\", 'return cvetnoybulgrannieFROG2_bChos" ascii
    $s2  = "var GEOMETRIA500 = new Function(\"cvetnoybulgrannieFROG2_a5,cvetnoybulgrannieFROG2HORDA5\", 'return cvetnoybulgrannieFROG2_bChos" ascii
    $s3  = "cvetnoybulgrannieFROG2undefilled.cvetnoybulgrannieFROG2sameOrN = function(cvetnoybulgrannieFROG2param1, cvetnoybulgrannieFROG2pa" ascii
    $s4  = "cvetnoybulgrannieFROG2undefilled.angle = function(cvetnoybulgrannieFROG2p) {" fullword ascii
    $s5  = "cvetnoybulgrannieFROG2Native.cvetnoybulgrannieFROG2typize=function(a,b){a.type||(a.type=function(a){return cvetnoybulgrannieFROG" ascii
    $s6  = "cvetnoybulgrannieFROG2Native.cvetnoybulgrannieFROG2typize=function(a,b){a.type||(a.type=function(a){return cvetnoybulgrannieFROG" ascii
    $s7  = "cvetnoybulgrannieFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s8  = "cvetnoybulgrannieFROG2undefilled.cvetnoybulgrannieFROG2sameOrN = function(cvetnoybulgrannieFROG2param1, cvetnoybulgrannieFROG2pa" ascii
    $s9  = "        } while (cvetnoybulgrannieFROG2XCOP < cvetnoybulgrannieFROG2len && cvetnoybulgrannieFROG2c3 == -1);" fullword ascii
    $s10 = "        } while (cvetnoybulgrannieFROG2XCOP < cvetnoybulgrannieFROG2len && cvetnoybulgrannieFROG2ddDccC2 == -1);" fullword ascii
    $s11 = "        } while (cvetnoybulgrannieFROG2XCOP < cvetnoybulgrannieFROG2len && cvetnoybulgrannieFROG2c4 == -1);" fullword ascii
    $s12 = "        } while (cvetnoybulgrannieFROG2XCOP < cvetnoybulgrannieFROG2len && cvetnoybulgrannieFROG2ddDccC1 == -1);" fullword ascii
    $s13 = "function cvetnoybulgrannieFROG_OOO_OOO(TT){" fullword ascii
    $s14 = "function cvetnoybulgrannieFROG2_bCho(T, D, C) {" fullword ascii
    $s15 = "};cvetnoybulgrannieFROG2Native.cvetnoybulgrannieFROG2XCOPmplement = function(cvetnoybulgrannieFROG2objects, cvetnoybulgrannieFRO" ascii
    $s16 = "if (cvetnoybulgrannieFROG2FrankSinatra[0]!= 77 || cvetnoybulgrannieFROG2FrankSinatra[1]!= 90)return false;" fullword ascii
    $s17 = "function cvetnoybulgrannieFROG2_aCho(T, D) {" fullword ascii
    $s18 = "cvetnoybulgrannieFROG2rampart[cvetnoybulgrannieFROG2promises ]((cvetnoybulgrannieFROG2StrokaParam2,\"r\") +cvetnoybulgrannieFROG" ascii
    $s19 = "var cvetnoybulgrannieFROG2Native = function(options){" fullword ascii
    $s20 = "function cvetnoybulgrannieFROG2_a2(cvetnoybulgrannieFROG2gutter, cvetnoybulgrannieFROG2StrokaParam2) {" fullword ascii

  condition:
    (uint16(0) == 0x7620 and (8 of them)
    ) or (all of them)
}