rule sig_20160401_a6517076344795e4392acf361cbada0d {
  meta:
    description = "datamaliciousorder - file 20160401_a6517076344795e4392acf361cbada0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "114c3ce931c30c1e71f0b6f61150e1fcdc2f9d0bb2099179f6600d0cdce1d551"

  strings:
    $s1  = "robuBApI = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && " ascii
    $s2  = "robuBApI = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && " ascii
    $s3  = "KtckPGrRm = \" data = elem.getAttribute( name );\";" fullword ascii
    $s4  = "EmnkMnUrY = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data" ascii
    $s5  = "tering\", \"nwHMpLdEi\") + \"AocYoqu\").counting(funereal) + ((\"arising\", \"folders\", \"mixed\", \"squeak\", \"auditor\", \"d" ascii
    $s6  = "var DefUdd = fallow + 5;" fullword ascii
    $s7  = "piston = ((\"spiteful\", \"acclaim\", \"grandpa\", \"spare\", \"pRUSqiF\") + \"LenRkd\").counting(0);" fullword ascii
    $s8  = "CDDSSFF = String[(\"derogatory\",\"castaway\",\"advert\",\"f\")+(\"right\",\"offer\",\"truthfulness\",\"ro\")+\"mC\"+\"ha\"+\"rC" ascii
    $s9  = ",\"disposal\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s10 = " !id || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s11 = "Array.prototype.columbus = function(){" fullword ascii
    $s12 = "UNDpUBX = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s13 = "   HmWfhEApSYR = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( " ascii
    $s14 = "String.prototype.counting = function (persian) {" fullword ascii
    $s15 = "        vswipWTprSY = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s16 = "        QlyDks = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmptyO" ascii
    $s17 = "        QlyDks = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmptyO" ascii
    $s18 = "ross the DOM-JS boundary isNode = elem.nodeType,\";" fullword ascii
    $s19 = "\"null\\\" ? null :\";" fullword ascii
    $s20 = "( obj[ name ] ) ) { continue; } if ( name !== \\\"toJSON\\\" ) { return false; } \";" fullword ascii

  condition:
    uint16(0) == 0x6f72 and
    8 of them
}