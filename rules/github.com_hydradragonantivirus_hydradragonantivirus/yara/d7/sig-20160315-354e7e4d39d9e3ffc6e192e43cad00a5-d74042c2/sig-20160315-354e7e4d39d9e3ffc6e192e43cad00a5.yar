rule sig_20160315_354e7e4d39d9e3ffc6e192e43cad00a5 {
  meta:
    description = "datamaliciousorder - file 20160315_354e7e4d39d9e3ffc6e192e43cad00a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8248afcb87c1cf1179c514a97d37243dc87fcd4627ecda9c8b74d148be2899e0"

  strings:
    $s1  = "farmer = LpWGlJC[3 * 5 - 3 * 3].split(\"tempestuous\").join(\"\");" fullword ascii
    $s2  = "    MrkdhRLW = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s3  = "gso\"+\"ns.com/8\"+\"7yg7\"+\"56f5\"+\".exe\", false);" fullword ascii
    $s4  = "h[5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s5  = "    IDMWcaoya.open((\"enigmatic\",\"combustion\",\"quench\",\"interstate\",\"G\")+\"ET\", (\"glossary\",\"lesson\",\"requirement" ascii
    $s6  = "feeling = ((\"vaccination\", \"gangbang\", \"ghOpxOkGz\", \"potentially\", \"pfOnDlHUvqI\") + \"LaokxSQUpI\").levitra();" fullword ascii
    $s7  = "String.prototype.levitra = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "IDMWcaoya.onreadystatechange = function () {" fullword ascii
    $s9  = "        KTyCmiP = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s10 = "StOovzDQTC = \" filter: {\";" fullword ascii
    $s11 = "var fUYPDb = this[farmer];" fullword ascii
    $s12 = " 0/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) ); " ascii
    $s13 = "emJJSvpXAWo = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s14 = "        KTyCmiP = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s15 = "    MrkdhRLW = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s16 = "        jdIopmVwiG = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s17 = "        LfEUUi = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s18 = "    DrYPDMGBl[LpWGlJC[claudiaI+1]](beNfYa, 1, \"UKKIdkchSks\" === \"dbOeUG\"); jgaoaArJr = \"  \\\"TAG\\\": function( nodeNameSe" ascii
    $s19 = "    sPYKTfclx = \"}    Return only captures needed by the pseudo filter method (type and argument)    return match.slice( 0, 3 )" ascii
    $s20 = "    sPYKTfclx = \"}    Return only captures needed by the pseudo filter method (type and argument)    return match.slice( 0, 3 )" ascii

  condition:
    uint16(0) == 0x524a and
    8 of them
}