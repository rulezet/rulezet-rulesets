rule sig_20160315_54aaac61bac7085fe35d4ab6ba04c863 {
  meta:
    description = "datamaliciousorder - file 20160315_54aaac61bac7085fe35d4ab6ba04c863.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d109b4cbbe5231b183238fd1e09a8462f4214235ba123c3e57f8fd35e4cc306c"

  strings:
    $s1  = "    IcxjrCrcb = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s2  = "midwinter = loLVAnpvq[3 * 5 - 3 * 3].split(\"celia\").join(\"\");" fullword ascii
    $s3  = " Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesi" ascii
    $s4  = "BzNxCJ.onreadystatechange = function () {" fullword ascii
    $s5  = "] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s6  = "s     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s7  = "        hynctbvbqS = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s8  = "zzle.error( match[0] );     \";" fullword ascii
    $s9  = "\"g.in/87y\")+(\"prefatory\",\"roller\",\"hungarian\",\"g7\")+(\"consensus\",\"limitation\",\"ringtones\",\"arabia\",\"56\")+\"f" ascii
    $s10 = "    BzNxCJ.open((\"plugins\",\"clairvoyance\",\"spence\",\"impacts\",\"G\")+\"ET\", (\"penitentiary\",\"deplore\",\"arbitrary\"," ascii
    $s11 = "eEMBRleU = \" filter: {\";" fullword ascii
    $s12 = "var DfcwA = this[midwinter];" fullword ascii
    $s13 = "1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );    " ascii
    $s14 = "        hynctbvbqS = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s15 = "String.prototype.specification = function () { return this.substr(0, 1); };" fullword ascii
    $s16 = "poXutlWrTsn = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s17 = "        YuaHrXBeWqr = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s18 = "    IcxjrCrcb = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s19 = "        XkhGXMTpMP = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s20 = "    CJkCDbNyQ[loLVAnpvq[delinquentI+1]](TMtga, 1, \"XBUCrWgtl\" === \"WfQoCEPE\"); epCCHcw = \"  \\\"TAG\\\": function( nodeName" ascii

  condition:
    uint16(0) == 0x4c6c and
    8 of them
}