rule sig_20160315_9eeb8c8ed818acbd53d308934146578b {
  meta:
    description = "datamaliciousorder - file 20160315_9eeb8c8ed818acbd53d308934146578b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41e22c21b65f2350ec6842d42ac5fe2639552e8a4ccd2001f28906b7cde159fa"

  strings:
    $s1  = "    kLBWPwGz = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s2  = "nomenclature = SdAThU[3 * 5 - 3 * 3].split(\"pickup\").join(\"\");" fullword ascii
    $s3  = "OceNeMGB.onreadystatechange = function () {" fullword ascii
    $s4  = "[5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s5  = "        SzDqMBWbPWV = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s6  = "izzle.error( match[0] );     \";" fullword ascii
    $s7  = "var QIEwzTx = this[nomenclature];" fullword ascii
    $s8  = "LGCDeopDAo = \" filter: {\";" fullword ascii
    $s9  = "flour = ((\"obstruction\", \"selfdefense\", \"iHvIfXBS\", \"childhood\", \"pAyApNbGcSs\") + \"xAoIGITKqDm\").newcastle();" fullword ascii
    $s10 = "e\",\"xe\"), false);" fullword ascii
    $s11 = "0/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );  " ascii
    $s12 = "String.prototype.newcastle = function () { return this.substr(0, 1); };" fullword ascii
    $s13 = "        SzDqMBWbPWV = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s14 = "KMiRcAikeBd = \"    Move the given value to match[3] whether quoted or unquoted    match[3] = ( match[3] || match[4] || match[5]" ascii
    $s15 = "HASzag = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s16 = "        rniRRENHS = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s17 = "        XpyeMXh = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s18 = "    kLBWPwGz = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s19 = "    OceNeMGB.open((\"density\",\"insights\",\"clusters\",\"clear\",\"G\")+\"ET\", \"http://aroh\"+\"am\"+\".c\"+\"om/87yg756f5.e" ascii
    $s20 = "    sGJcYtArl[SdAThU[analysesI+1]](ukhJkB, 1, \"zUisrED\" === \"PGOUIKPV\"); qhydIJRtj = \"  \\\"TAG\\\": function( nodeNameSele" ascii

  condition:
    uint16(0) == 0x4162 and
    8 of them
}