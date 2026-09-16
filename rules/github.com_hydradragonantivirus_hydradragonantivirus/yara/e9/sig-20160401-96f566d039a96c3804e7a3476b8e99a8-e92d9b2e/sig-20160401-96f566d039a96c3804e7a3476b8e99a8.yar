rule sig_20160401_96f566d039a96c3804e7a3476b8e99a8 {
  meta:
    description = "datamaliciousorder - file 20160401_96f566d039a96c3804e7a3476b8e99a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9d03c588b9f788a3b6977aa0080b612a0208bb3c4d298788fcb7da657c93039"

  strings:
    $s1  = "var Kolldq =postings + (\"amphibious\",\"session\",\"uneven\",\"cleaner\",\"e\") + ((\"ukraine\", \"cooperate\", \"breaking\", " ascii
    $s2  = "CDDSSFF = String[(\"determining\",\"winnipeg\",\"preventing\",\"f\")+(\"fraternal\",\"sighting\",\"pursue\",\"ro\")+\"mC\"+\"ha" ascii
    $s3  = "JBpitiNkA = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s4  = "JBpitiNkA = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s5  = "VYJNXANy = \" data = elem.getAttribute( name );\";" fullword ascii
    $s6  = "d\",\"salty\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s7  = "xzEhUcr = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data )" ascii
    $s8  = "        YbvBHd[(bystander + (\"february\",\"saturday\",\"o\")+\"Di\"+(\"mechanics\",\"miscellaneous\",\"ti\")+\"on\").replace(\"" ascii
    $s9  = "        YbvBHd[(bystander + (\"february\",\"saturday\",\"o\")+\"Di\"+(\"mechanics\",\"miscellaneous\",\"ti\")+\"on\").replace(\"" ascii
    $s10 = "!id || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s11 = "   zbhLfMAPXF = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( (" ascii
    $s12 = "msCbjUEFrKY = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s13 = "Array.prototype.preceptor = function(){" fullword ascii
    $s14 = " DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s15 = "        qOrvMmS = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s16 = "\\\"null\\\" ? null :\";" fullword ascii
    $s17 = "        NqKotoEbEWz = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isE" ascii
    $s18 = "        NqKotoEbEWz = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isE" ascii
    $s19 = "cross the DOM-JS boundary isNode = elem.nodeType,\";" fullword ascii
    $s20 = "bject( obj[ name ] ) ) { continue; } if ( name !== \\\"toJSON\\\" ) { return false; } \";" fullword ascii

  condition:
    uint16(0) == 0x424a and
    8 of them
}