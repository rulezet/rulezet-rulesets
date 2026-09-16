rule sig_20160401_a16737bf6e7f5fd0f0bdc05e6416f303 {
  meta:
    description = "datamaliciousorder - file 20160401_a16737bf6e7f5fd0f0bdc05e6416f303.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bc763d0ce264df46a3c8883fdb4a8b96230106faf80d5934cccadcc30634b76"

  strings:
    $s1  = "CDDSSFF = String[(\"insurgents\",\"opponents\",\"necessary\",\"f\")+(\"zenith\",\"wring\",\"respondent\",\"ro\")+\"mC\"+\"ha\"+" ascii
    $s2  = "EtadsDu = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && e" ascii
    $s3  = "EtadsDu = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && e" ascii
    $s4  = "s\",\"complaint\",\"adjustments\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s5  = "zztAhiXrq = \" data = elem.getAttribute( name );\";" fullword ascii
    $s6  = "\", \"nwHMpLdEi\") + \"AocYoqu\").cranium(bashful) + ((\"voluptuousness\", \"villager\", \"batch\", \"cosmetics\", \"offender\"," ascii
    $s7  = "zakxUr = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data ) " ascii
    $s8  = "CDDSSFF = String[(\"insurgents\",\"opponents\",\"necessary\",\"f\")+(\"zenith\",\"wring\",\"respondent\",\"ro\")+\"mC\"+\"ha\"+" ascii
    $s9  = "phases = ((\"inverse\", \"evaluation\", \"mechanic\", \"leaked\", \"pVKDkRECSkGx\") + \"luoMvmodI\").cranium(0);" fullword ascii
    $s10 = "var Kolldq =couponss + (\"scouring\",\"humans\",\"dirty\",\"crane\",\"e\") + ((\"jokes\", \"tawny\", \"kaleidoscope\", \"brookly" ascii
    $s11 = "d || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s12 = "   btoCIneD = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !" ascii
    $s13 = "Array.prototype.fervor = function(){" fullword ascii
    $s14 = "TPDJdK = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s15 = "        hgtSACTWn[\"w\"+\"ri\"+(\"sweeps\",\"crowbar\",\"admissions\",\"rhodes\",\"te\")](AIPIV[\"\"+(\"thrashing\",\"presidenti" ascii
    $s16 = "String.prototype.cranium = function (odysseus) {" fullword ascii
    $s17 = " DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s18 = "        WgfLHkmfzYy = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s19 = "        RVtMpz = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmptyO" ascii
    $s20 = "        RVtMpz = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmptyO" ascii

  condition:
    uint16(0) == 0x7445 and
    8 of them
}