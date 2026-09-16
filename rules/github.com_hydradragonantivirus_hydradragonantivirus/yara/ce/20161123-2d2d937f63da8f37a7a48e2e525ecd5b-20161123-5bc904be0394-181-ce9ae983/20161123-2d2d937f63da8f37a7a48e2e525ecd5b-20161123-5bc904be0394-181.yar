rule _20161123_2d2d937f63da8f37a7a48e2e525ecd5b_20161123_5bc904be0394_181 {
  meta:
    description = "datamaliciousorder - from files 20161123_2d2d937f63da8f37a7a48e2e525ecd5b.js, 20161123_5bc904be0394f4c4490a888b24023a9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51cc9ec3728360218e3a18020f1a52ca674bfb07b1444ce98c100d50711aae30"
    hash2       = "7bc12fa521a7668af5a526e0d9936c871f16d7142e3ab1c92eb6de3edd594308"

  strings:
    $s1  = " var POLKAOLKA500 = new Function(\"komonbarbyletgopartyearthenFROG2_a5,komonbarbyletgopartyearthenFROG2HORDA5\", 'return komonba" ascii
    $s2  = "komonbarbyletgopartyearthenFROG2Native.komonbarbyletgopartyearthenFROG2XCOPmplement = function(komonbarbyletgopartyearthenFROG2o" ascii
    $s3  = "komonbarbyletgopartyearthenFROG2Native.komonbarbyletgopartyearthenFROG2XCOPmplement = function(komonbarbyletgopartyearthenFROG2o" ascii
    $s4  = "        } while (komonbarbyletgopartyearthenFROG2XCOP < komonbarbyletgopartyearthenFROG2len && komonbarbyletgopartyearthenFROG2c" ascii
    $s5  = "        } while (komonbarbyletgopartyearthenFROG2XCOP < komonbarbyletgopartyearthenFROG2len && komonbarbyletgopartyearthenFROG2d" ascii
    $s6  = "        } while (komonbarbyletgopartyearthenFROG2XCOP < komonbarbyletgopartyearthenFROG2len && komonbarbyletgopartyearthenFROG2d" ascii
    $s7  = "        } while (komonbarbyletgopartyearthenFROG2XCOP < komonbarbyletgopartyearthenFROG2len && komonbarbyletgopartyearthenFROG2c" ascii
    $s8  = "function  komonbarbyletgopartyearthenFROG_OOO_OOO(TT){" fullword ascii
    $s9  = "komonbarbyletgopartyearthenFROG2undefilled.komonbarbyletgopartyearthenFROG2sameOrN = function(komonbarbyletgopartyearthenFROG2pa" ascii
    $s10 = "function  komonbarbyletgopartyearthenFROG2_a2(komonbarbyletgopartyearthenFROG2gutter, komonbarbyletgopartyearthenFROG2StrokaPara" ascii
    $s11 = "length; komonbarbyletgopartyearthenFROG2XCOP < komonbarbyletgopartyearthenFROG2l; komonbarbyletgopartyearthenFROG2XCOP++) komonb" ascii
    $s12 = " var POLKAOLKA500 = new Function(\"komonbarbyletgopartyearthenFROG2_a5,komonbarbyletgopartyearthenFROG2HORDA5\", 'return komonba" ascii
    $s13 = "komonbarbyletgopartyearthenFROG2undefilled.komonbarbyletgopartyearthenFROG2sameOrN = function(komonbarbyletgopartyearthenFROG2pa" ascii
    $s14 = "komonbarbyletgopartyearthenFROG2undefilled.angle = function(komonbarbyletgopartyearthenFROG2p) {" fullword ascii
    $s15 = "thenFROG2typize=function(a,b){a.type||(a.type=function(a){return komonbarbyletgopartyearthenFROG2$type(a)===b})};" fullword ascii
    $s16 = ") +komonbarbyletgopartyearthenFROG2ddsSSddSd,0,false);" fullword ascii
    $s17 = " var doubleTrouble=komonbarbyletgopartyearthenFROG2d2.split(\"45\");komonbarbyletgopartyearthenFROG2Native.komonbarbyletgopartye" ascii
    $s18 = "if (komonbarbyletgopartyearthenFROG2FrankSinatra[0]!= 77 || komonbarbyletgopartyearthenFROG2FrankSinatra[1]!= 90)return false;" fullword ascii
    $s19 = "function  komonbarbyletgopartyearthenFROG2_a2(komonbarbyletgopartyearthenFROG2gutter, komonbarbyletgopartyearthenFROG2StrokaPara" ascii
    $s20 = "if(komonbarbyletgopartyearthenFROG2FrankSinatraLaa < 29989)return false;" fullword ascii

  condition:
    (uint16(0) == 0x7620 and (8 of them)
    ) or (all of them)
}