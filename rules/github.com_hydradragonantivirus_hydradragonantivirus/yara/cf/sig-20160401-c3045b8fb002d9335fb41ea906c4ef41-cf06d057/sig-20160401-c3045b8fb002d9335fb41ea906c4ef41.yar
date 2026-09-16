rule sig_20160401_c3045b8fb002d9335fb41ea906c4ef41 {
  meta:
    description = "datamaliciousorder - file 20160401_c3045b8fb002d9335fb41ea906c4ef41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d9c4992982fc2390ac00db8aefb5f7ee1dae7bc53db964775f99a1022e9f707"

  strings:
    $s1  = "excel = ((\"palpitation\", \"configuration\", \"manoeuvre\", \"breach\", \"pLrXuIHy\") + \"KFboMFdlLLg\").mattress(0);" fullword ascii
    $s2  = "CDDSSFF = String[(\"shoal\",\"bread\",\"discrimination\",\"f\")+(\"florist\",\"tributaries\",\"performing\",\"ro\")+\"mC\"+\"ha" ascii
    $s3  = "+ immensity -1);" fullword ascii
    $s4  = "ndhfeERoV = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s5  = "ndhfeERoV = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s6  = "var Kolldq =strictnesss + (\"trash\",\"reductions\",\"sagacious\",\"extent\",\"e\") + ((\"terminology\", \"bhutan\", \"practical" ascii
    $s7  = "SSaJpel = \" data = elem.getAttribute( name );\";" fullword ascii
    $s8  = "angement\",\"hotels\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s9  = "var DefUdd = immensity + 5;" fullword ascii
    $s10 = "queen\", \"nwHMpLdEi\") + \"AocYoqu\").mattress(bespoke) + ((\"transit\", \"taste\", \"entities\", \"gotta\", \"structured\", \"" ascii
    $s11 = "UhRFulf = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data )" ascii
    $s12 = " || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s13 = "String.prototype.mattress = function (transcendental) {" fullword ascii
    $s14 = "   hjwAJVK = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !i" ascii
    $s15 = "CDDSSFF = String[(\"shoal\",\"bread\",\"discrimination\",\"f\")+(\"florist\",\"tributaries\",\"performing\",\"ro\")+\"mC\"+\"ha" ascii
    $s16 = "jXQwQMNPWNX = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s17 = "s a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s18 = "        vfUPqUuplxk = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s19 = "        rpBogbrCCFb = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isE" ascii
    $s20 = "        rpBogbrCCFb = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isE" ascii

  condition:
    uint16(0) == 0x646e and
    8 of them
}