rule sig_20160315_6ad5110054ea30ee9b6cd7043a90f6f8 {
  meta:
    description = "datamaliciousorder - file 20160315_6ad5110054ea30ee9b6cd7043a90f6f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48cfec994c052396d20e85e44f407133cf5436075e2b7288d89c5153bb8c86e1"

  strings:
    $s1  = "    PAKHncVOd = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s2  = "travel = pGkzXA[3 * 5 - 3 * 3].split(\"frequently\").join(\"\");" fullword ascii
    $s3  = " Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesi" ascii
    $s4  = "dlyWPUICo.onreadystatechange = function () {" fullword ascii
    $s5  = "    dlyWPUICo.open(\"G\"+(\"coerce\",\"participate\",\"ET\"), (\"allows\",\"overtime\",\"htt\")+\"p://gargso\"+\"ns.com/87y\"+\"" ascii
    $s6  = "] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s7  = "s     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s8  = "String.prototype.rosette = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "        DKgYlf = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      S" ascii
    $s10 = "qVLbwNsJeKF = \" filter: {\";" fullword ascii
    $s11 = "var JHFUvzNf = this[travel];" fullword ascii
    $s12 = "1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );    " ascii
    $s13 = "DEdNpKwLhh = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s14 = "        DKgYlf = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      S" ascii
    $s15 = ".error( match[0] );     \";" fullword ascii
    $s16 = "        hvaidJmj = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s17 = "    PAKHncVOd = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s18 = "        vtQsXh = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s19 = "    aRVcEI[pGkzXA[debasementI+1]](sHtRDwl, 1, \"uRGOlaA\" === \"EXztbowtYKo\"); PQjaPpp = \"  \\\"TAG\\\": function( nodeNameSel" ascii
    $s20 = "} catch (EOSbm) { };" fullword ascii

  condition:
    uint16(0) == 0x5245 and
    8 of them
}