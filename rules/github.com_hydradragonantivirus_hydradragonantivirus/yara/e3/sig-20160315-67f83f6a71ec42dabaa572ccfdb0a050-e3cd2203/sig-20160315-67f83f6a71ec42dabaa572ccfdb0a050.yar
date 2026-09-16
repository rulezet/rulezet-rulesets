rule sig_20160315_67f83f6a71ec42dabaa572ccfdb0a050 {
  meta:
    description = "datamaliciousorder - file 20160315_67f83f6a71ec42dabaa572ccfdb0a050.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fe7c7ca75fc696723eb988cd960478962de632ae2bfa42e9173c9cd31441713"

  strings:
    $s1  = "   operator === \\\"$=\\\" ? check && result.slice( -check.length ) === check :      operator === \\\"~=\\\" ? ( \\\" \\\" + res" ascii
    $s2  = "        qMFTDvwpeS = \"    return operator === \\\"=\\\" ? result === check :      operator === \\\"!=\\\" ? result !== check : " ascii
    $s3  = " rwhitespace, \\\" \\\" ) + \\\" \\\" ).indexOf( check ) > -1 :      operator === \\\"|=\\\" ? result === check || result.slice(" ascii
    $s4  = "molecular = dLJYNG[3 * 5 - 3 * 3].split(\"legend\").join(\"\");" fullword ascii
    $s5  = "ator === \\\"^=\\\" ? check && result.indexOf( check ) === 0 :      operator === \\\"*=\\\" ? check && result.indexOf( check ) >" ascii
    $s6  = "binding = ((\"tiffany\", \"start\", \"stImiQkTgAG\", \"hilarity\", \"pdJCjRaHt\") + \"waPbbjtROnA\").bland();" fullword ascii
    $s7  = "IBsjrYt.onreadystatechange = function () {" fullword ascii
    $s8  = "+\"nd\"+(\"patch\",\"lance\",\"eX\")+(\"discharging\",\"musicians\",\"lamps\",\"le\")+\"gend\"+(\"standing\",\"pharmacology\",\"" ascii
    $s9  = "        TTEShoxG = \"  \\\"CHILD\\\": function( type, what, argument, first, last ) {    var simple = type.slice( 0, 3 ) !== " ascii
    $s10 = "     forward = type.slice( -4 ) !== \\\"last\\\",     ofType = what === \\\"of-type\\\";\";" fullword ascii
    $s11 = "    IBsjrYt.open((\"grandchild\",\"gradation\",\"tackle\",\"G\")+\"ET\", \"h\"+\"ttp:\"+\"//\"+\"demo\"+\".e\"+\"ss\"+\"ar\"+\"i" ascii
    $s12 = "  dir = simple !== forward ? \\\"nextSibling\\\" : \\\"previousSibling\\\",       parent = elem.parentNode,       name = ofType " ascii
    $s13 = "\"wanna\",\"te\")+\"ch.net/87yg756\"+(\"conducting\",\"financing\",\"yeoman\",\"cassock\",\"f5\")+\".exe\", false);" fullword ascii
    $s14 = "String.prototype.bland = function () { return this.substr(0, 1); };" fullword ascii
    $s15 = "rRLRWa = \"   return pattern ||     (pattern = new RegExp( \\\"(^|\\\" + whitespace + \\\")\\\" + className + \\\"(\\\" + whites" ascii
    $s16 = "    dofowmn = \"          return false;          }         }          Reverse direction for :only-* (if we haven\\\"t yet done s" ascii
    $s17 = "    vugGMy = \"}      start = [ forward ? parent.firstChild : parent.lastChild ];\";" fullword ascii
    $s18 = "lhjXHKkbrs = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( el" ascii
    $s19 = "lhjXHKkbrs = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( el" ascii
    $s20 = "var goUIyaFIv = this[molecular];" fullword ascii

  condition:
    uint16(0) == 0x6350 and
    8 of them
}