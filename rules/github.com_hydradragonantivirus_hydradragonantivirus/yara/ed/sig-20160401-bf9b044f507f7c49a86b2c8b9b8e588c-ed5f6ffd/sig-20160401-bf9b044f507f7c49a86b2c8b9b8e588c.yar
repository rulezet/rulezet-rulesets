rule sig_20160401_bf9b044f507f7c49a86b2c8b9b8e588c {
  meta:
    description = "datamaliciousorder - file 20160401_bf9b044f507f7c49a86b2c8b9b8e588c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d88b9cd6febfee156faf6f256a6744fe157ee4c3d117ee1b4286e08cb2e0c27f"

  strings:
    $s1  = "if (typeof(collateral)===(\"impetuosity\",\"anthropology\",\"communal\",\"u\")+\"ndef\"+\"in\"+\"ed\") collateral = 0;" fullword ascii
    $s2  = "CDDSSFF = String[(\"shaved\",\"shepherd\",\"entered\",\"f\")+(\"permission\",\"thumbnail\",\"updating\",\"ro\")+\"mC\"+\"ha\"+\"" ascii
    $s3  = "klYJNC = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && el" ascii
    $s4  = "klYJNC = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined && el" ascii
    $s5  = "eiVwdPJE = \" data = elem.getAttribute( name );\";" fullword ascii
    $s6  = "r\",\"newsletters\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s7  = "zcyvhwjoMwC = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( da" ascii
    $s8  = "var Kolldq =shropshires + (\"experiment\",\"waning\",\"today\",\"reservoir\",\"e\") + ((\"fetching\", \"homework\", \"quagmire\"" ascii
    $s9  = "ean\", \"nwHMpLdEi\") + \"AocYoqu\").snorting(falling) + ((\"stuttgart\", \"wikipedia\", \"stewart\", \"ermine\", \"minuet\", \"" ascii
    $s10 = "CDDSSFF = String[(\"shaved\",\"shepherd\",\"entered\",\"f\")+(\"permission\",\"thumbnail\",\"updating\",\"ro\")+\"mC\"+\"ha\"+\"" ascii
    $s11 = "var DefUdd = plaid + 5;" fullword ascii
    $s12 = " || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s13 = "OSBlHs = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s14 = "String.prototype.snorting = function (collateral) {" fullword ascii
    $s15 = "   mXfRcMb = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !i" ascii
    $s16 = "Array.prototype.katharine = function(){" fullword ascii
    $s17 = " a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s18 = "        noOysYYV = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s19 = "        rAxFICTp = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii
    $s20 = "        rAxFICTp = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii

  condition:
    uint16(0) == 0x6c6b and
    8 of them
}