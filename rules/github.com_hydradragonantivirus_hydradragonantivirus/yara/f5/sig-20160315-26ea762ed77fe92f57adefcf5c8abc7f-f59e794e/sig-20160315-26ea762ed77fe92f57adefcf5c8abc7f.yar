rule sig_20160315_26ea762ed77fe92f57adefcf5c8abc7f {
  meta:
    description = "datamaliciousorder - file 20160315_26ea762ed77fe92f57adefcf5c8abc7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33271aad6f44cd68e62cd5e0c6a5c7d4a59bd612246a874b23aff971b4dfd754"

  strings:
    $s1  = "    KGgRtYkb = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s2  = "bibliography = igcWY[3 * 5 - 3 * 3].split(\"married\").join(\"\");" fullword ascii
    $s3  = "forced = ((\"flags\", \"berne\", \"hiMpLtp\", \"ebook\", \"pmTXUXzlVIiy\") + \"LwAlpUDc\").fails();" fullword ascii
    $s4  = "LYDAmcyY.onreadystatechange = function () {" fullword ascii
    $s5  = "String.prototype.fails = function () { return this.substr(0, 1); };" fullword ascii
    $s6  = "5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s7  = "therell\",\"blizzard\",\".ma\")+\"rriedXMmarriedLH\"+(\"scary\",\"accuser\",\"essex\",\"candles\",\"ma\")+(\"springfield\",\"bri" ascii
    $s8  = "        bgiliGz = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s9  = "\"a.\"+\"co\"+\"m/\"+\"87\"+(\"vaunting\",\"hydraulic\",\"eclat\",\"yg756f\")+\"5.\"+\"exe\", false);" fullword ascii
    $s10 = "qIQFpRGbHl = \" filter: {\";" fullword ascii
    $s11 = "    GfUDg[igcWY[internalI+1]](DuzRtGgX, 1, \"eVSlmXoSm\" === \"TcRqwd\"); tMPYWxu = \"  \\\"TAG\\\": function( nodeNameSelector " ascii
    $s12 = "var BBYAXG = this[bibliography];" fullword ascii
    $s13 = "/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );   " ascii
    $s14 = "tVCzLurOVO = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s15 = "        bgiliGz = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s16 = "        OWrdAE = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s17 = "    KGgRtYkb = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s18 = "        vIAWqvV = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s19 = "    GfUDg[igcWY[internalI+1]](DuzRtGgX, 1, \"eVSlmXoSm\" === \"TcRqwd\"); tMPYWxu = \"  \\\"TAG\\\": function( nodeNameSelector " ascii
    $s20 = "} catch (hBqUdv) { };" fullword ascii

  condition:
    uint16(0) == 0x5361 and
    8 of them
}