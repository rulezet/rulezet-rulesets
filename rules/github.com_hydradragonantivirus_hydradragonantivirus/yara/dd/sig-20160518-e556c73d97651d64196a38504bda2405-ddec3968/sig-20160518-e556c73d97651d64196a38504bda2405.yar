rule sig_20160518_e556c73d97651d64196a38504bda2405 {
  meta:
    description = "datamaliciousorder - file 20160518_e556c73d97651d64196a38504bda2405.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3d3f54d726d53706ecde1222ff8b622a24d7e1121d38d4ccfafcf94dfecd86a"

  strings:
    $s1  = "var secret = [before, clown,cacique,  \"\"+\".\"+(\"hotel\",\"container\",\"lombardy\",\"complacent\",\"spokesman\",\"remainder" ascii
    $s2  = "banter = banter+ secret.shift();" fullword ascii
    $s3  = "var excited = secret.pop().split(\">\");" fullword ascii
    $s4  = "var welch=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".gunther4())&&sentences[\"c3RhdHVz\".gunther4()] +\"\"==\"MjAw\".gunthe" ascii
    $s5  = "weasel = ((\"conclave\", \"belly\", \"signet\", \"pyramidal\", \"ELzDHgLmd\") + \"OzycRuF\").gunther2();" fullword ascii
    $s6  = "toxic = ((\"surplice\", \"potentially\", \"stench\", \"laurels\", \"sGbAnJlzGN\") + \"GfCounQsq\").gunther2();" fullword ascii
    $s7  = "        var ecclesiastes = new deplore(((\"swagger\",\"uncover\",\"passing\",\"nondescript\",\"sedan\",\"suffix\",\"fraser\",\"a" ascii
    $s8  = "String.prototype.gunther2 = function () {" fullword ascii
    $s9  = "var somebody = surfaces[secret.shift()](secret.shift());" fullword ascii
    $s10 = "String.prototype.gunther4 = function() {" fullword ascii
    $s11 = "surfaces[secret.shift()](banter, abatement, true);" fullword ascii
    $s12 = "String.prototype.gunther = function () {" fullword ascii
    $s13 = "var deplore = this[secret.shift()];" fullword ascii
    $s14 = "            sentences[corset]((\"materialistic\",\"jackson\",\"G\" + weasel) + (\"reporter\",\"relaxing\",\"timed\",\"jennifer\"" ascii
    $s15 = "            sentences[corset]((\"materialistic\",\"jackson\",\"G\" + weasel) + (\"reporter\",\"relaxing\",\"timed\",\"jennifer\"" ascii
    $s16 = "imed\",\"figures\",\"internship\",\"intoxicating\",\"prescription\",\"supplant\",\"carnage\",\"P>\")+\"WU\"+(\"mounting\",\"vulg" ascii
    $s17 = "var abatement = 6/6;" fullword ascii
    $s18 = "var sentences = new deplore(excited[0]);" fullword ascii
    $s19 = "        var ecclesiastes = new deplore(((\"swagger\",\"uncover\",\"passing\",\"nondescript\",\"sedan\",\"suffix\",\"fraser\",\"a" ascii
    $s20 = "var before = \"QWdeferentialN0aXZdeferentiallWE9iadeferentialmVjdA=deferential=\".gunther4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}