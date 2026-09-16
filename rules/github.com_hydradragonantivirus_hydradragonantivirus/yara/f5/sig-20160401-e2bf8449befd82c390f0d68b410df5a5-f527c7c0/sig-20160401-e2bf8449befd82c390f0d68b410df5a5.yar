rule sig_20160401_e2bf8449befd82c390f0d68b410df5a5 {
  meta:
    description = "datamaliciousorder - file 20160401_e2bf8449befd82c390f0d68b410df5a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0dc173ef66dc1c617ee40db7abce1db954367fa40d83f1b1f517207aea82400"

  strings:
    $s1  = "CDDSSFF = String[(\"acoustic\",\"varying\",\"emissary\",\"f\")+(\"respiratory\",\"expected\",\"civilian\",\"ro\")+\"mC\"+\"ha\"+" ascii
    $s2  = "dictum = ((\"level\", \"importation\", \"elation\", \"silly\", \"pVtCyKiWY\") + \"PnOfyATto\").cooked(0);" fullword ascii
    $s3  = "raLKhvRgtrx = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined " ascii
    $s4  = "RkwfGXk = \" data = elem.getAttribute( name );\";" fullword ascii
    $s5  = "raLKhvRgtrx = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined " ascii
    $s6  = "CDDSSFF = String[(\"acoustic\",\"varying\",\"emissary\",\"f\")+(\"respiratory\",\"expected\",\"civilian\",\"ro\")+\"mC\"+\"ha\"+" ascii
    $s7  = "WCLeFOe = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data )" ascii
    $s8  = "ing\", \"nwHMpLdEi\") + \"AocYoqu\").cooked(lover) + ((\"assembled\", \"continuity\", \"presuppose\", \"merge\", \"woolly\", \"d" ascii
    $s9  = ",\"naming\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s10 = "|| !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s11 = "   coCQoJ = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !id" ascii
    $s12 = "XfrBsD = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s13 = "Array.prototype.converted = function(){" fullword ascii
    $s14 = "String.prototype.cooked = function (parsimony) {" fullword ascii
    $s15 = " a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s16 = "        jvTtfThTOc = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s17 = "        XvSTvokF = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii
    $s18 = "        XvSTvokF = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii
    $s19 = "ull\\\" ? null :\";" fullword ascii
    $s20 = "ct( obj[ name ] ) ) { continue; } if ( name !== \\\"toJSON\\\" ) { return false; } \";" fullword ascii

  condition:
    uint16(0) == 0x6172 and
    8 of them
}