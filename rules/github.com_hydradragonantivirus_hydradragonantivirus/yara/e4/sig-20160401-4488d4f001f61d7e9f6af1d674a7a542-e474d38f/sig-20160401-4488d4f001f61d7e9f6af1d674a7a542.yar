rule sig_20160401_4488d4f001f61d7e9f6af1d674a7a542 {
  meta:
    description = "datamaliciousorder - file 20160401_4488d4f001f61d7e9f6af1d674a7a542.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad7d569e89e6799fb4e2edc0a4d203577a06f2c6057a8096ab45138da784d576"

  strings:
    $s1  = "CDDSSFF = String[(\"fisting\",\"worship\",\"reporting\",\"f\")+(\"extirpate\",\"indebtedness\",\"birthright\",\"ro\")+\"mC\"+\"h" ascii
    $s2  = "7 + animate -1);" fullword ascii
    $s3  = "importation = ((\"beckon\", \"atlanta\", \"seems\", \"prohibit\", \"pLtIguNgCYwh\") + \"GrFhpw\").dictionary(0);" fullword ascii
    $s4  = "PNPwKRGWp = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s5  = "PNPwKRGWp = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s6  = "YrWoQjRFn = \" data = elem.getAttribute( name );\";" fullword ascii
    $s7  = "            DWHjkM[(annie).reverse().join(\"\")]((\"entries\",\"contemn\",\"cleaner\",\"G\") + numerouse + (\"experiencing\",\"h" ascii
    $s8  = "OWyOLuMW = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data " ascii
    $s9  = "var DefUdd = animate + 5;" fullword ascii
    $s10 = "            DWHjkM[(annie).reverse().join(\"\")]((\"entries\",\"contemn\",\"cleaner\",\"G\") + numerouse + (\"experiencing\",\"h" ascii
    $s11 = "ive\",\"modicum\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s12 = "    visible.puppies = visible.philology[(\"c\"+\"hD\"+\"rA\"+(\"denver\",\"siddhartha\",\"solvent\",\"t\")).replace(\"D\", CDDSS" ascii
    $s13 = "d || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s14 = "Array.prototype.bereavement = function(){" fullword ascii
    $s15 = "CDDSSFF = String[(\"fisting\",\"worship\",\"reporting\",\"f\")+(\"extirpate\",\"indebtedness\",\"birthright\",\"ro\")+\"mC\"+\"h" ascii
    $s16 = "exjqgoXoGH = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s17 = "   mCGkNicr = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !" ascii
    $s18 = "String.prototype.dictionary = function (necessary) {" fullword ascii
    $s19 = " DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s20 = "        PUJNPLXXijE = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii

  condition:
    uint16(0) == 0x4e50 and
    8 of them
}