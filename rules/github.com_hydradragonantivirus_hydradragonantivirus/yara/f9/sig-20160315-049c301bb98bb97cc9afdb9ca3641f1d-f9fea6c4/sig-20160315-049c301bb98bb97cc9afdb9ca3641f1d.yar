rule sig_20160315_049c301bb98bb97cc9afdb9ca3641f1d {
  meta:
    description = "datamaliciousorder - file 20160315_049c301bb98bb97cc9afdb9ca3641f1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7564dbf3ccda8de959417c2c4775473ea1afae24428e0fcbd47c74f63de88fe"

  strings:
    $s1  = "    cwBwOuRfDW = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s2  = "equivalent = PlgADipoU[3 * 5 - 3 * 3].split(\"sparc\").join(\"\");" fullword ascii
    $s3  = "VeEWSo.onreadystatechange = function () {" fullword ascii
    $s4  = "  Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthes" ascii
    $s5  = "= +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s6  = "finder = ((\"framing\", \"rebound\", \"uOQmCGJuMwH\", \"thoughtfulness\", \"psinFKDr\") + \"TwMQLlsJ\").routers();" fullword ascii
    $s7  = "String.prototype.routers = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "is     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s9  = "        qOmjqvyz = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {     " ascii
    $s10 = "var ilgBb = this[equivalent];" fullword ascii
    $s11 = "\"testimonial\",\"flowers\",\"queenly\",\"fujitsu\",\".e\")+\"xe\", false);" fullword ascii
    $s12 = "uInmnQtI = \" filter: {\";" fullword ascii
    $s13 = "    match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );     m" ascii
    $s14 = "oYtiboH = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s15 = "        qOmjqvyz = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {     " ascii
    $s16 = "        oBOdyaDuNI = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s17 = "    cwBwOuRfDW = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s18 = "        rodhxQPfdST = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s19 = "le.error( match[0] );     \";" fullword ascii
    $s20 = "    VeEWSo.open(\"G\"+(\"transexuales\",\"candlestick\",\"ET\"), \"h\"+\"tt\"+(\"ranks\",\"banner\",\"purify\",\"detract\",\"p:" ascii

  condition:
    uint16(0) == 0x7371 and
    8 of them
}