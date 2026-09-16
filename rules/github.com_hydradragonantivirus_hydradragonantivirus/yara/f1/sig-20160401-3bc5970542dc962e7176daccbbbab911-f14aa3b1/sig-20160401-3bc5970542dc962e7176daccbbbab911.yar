rule sig_20160401_3bc5970542dc962e7176daccbbbab911 {
  meta:
    description = "datamaliciousorder - file 20160401_3bc5970542dc962e7176daccbbbab911.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ce5ae772ab6e062d27f85ec612fcf6b46f05330a8b7df85f35583744ab3c587"

  strings:
    $s1  = "poster) + \"\";" fullword ascii
    $s2  = "String.prototype.quasi = function (poster) {" fullword ascii
    $s3  = "CDDSSFF = String[(\"adaptation\",\"electro\",\"milwaukee\",\"f\")+(\"fatality\",\"grill\",\"arctic\",\"ro\")+\"mC\"+\"ha\"+\"rC" ascii
    $s4  = "rlUtFsWiYAR = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined " ascii
    $s5  = "endorsed = ((\"filling\", \"piquant\", \"desperado\", \"importation\", \"pGMwoTogehY\") + \"xQKsiJdui\").quasi(0);" fullword ascii
    $s6  = "if (typeof(poster)===(\"basis\",\"sweater\",\"wallpaper\",\"u\")+\"ndef\"+\"in\"+\"ed\") poster = 0;" fullword ascii
    $s7  = "SGIJmUj = \" data = elem.getAttribute( name );\";" fullword ascii
    $s8  = "    gloucestershire.coupon = gloucestershire.crouch[(\"c\"+\"hD\"+\"rA\"+(\"informant\",\"deacon\",\"monster\",\"t\")).replace(" ascii
    $s9  = "CDDSSFF = String[(\"adaptation\",\"electro\",\"milwaukee\",\"f\")+(\"fatality\",\"grill\",\"arctic\",\"ro\")+\"mC\"+\"ha\"+\"rC" ascii
    $s10 = "nWUhsvzKG = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data" ascii
    $s11 = "nous\",\"electrode\",\"bacon\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s12 = "var DefUdd = imprison + 5;" fullword ascii
    $s13 = "rlUtFsWiYAR = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined " ascii
    $s14 = "onitors\", \"nwHMpLdEi\") + \"AocYoqu\").quasi(criticism) + ((\"drawback\", \"protocols\", \"thrash\", \"sonic\", \"requital\", " ascii
    $s15 = " || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s16 = "Array.prototype.tightening = function(){" fullword ascii
    $s17 = "var Kolldq =sentencess + (\"forums\",\"cartridges\",\"fluently\",\"portend\",\"e\") + ((\"doublet\", \"clearance\", \"largest\"," ascii
    $s18 = "   hTrmtxX = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !i" ascii
    $s19 = "uWHyihPTzA = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s20 = "        var strapping = BSfuntnX + \"/\" + flower + ETWPF.shift();" fullword ascii

  condition:
    uint16(0) == 0x6c72 and
    8 of them
}