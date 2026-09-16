rule sig_20160518_19e2e771a89d5d6f201326edd5fb623e {
  meta:
    description = "datamaliciousorder - file 20160518_19e2e771a89d5d6f201326edd5fb623e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128787531e8fecf5b4054d24d5acd15950de42b98914f191c81210acbe2ceac6"

  strings:
    $s1  = "var indefatigable = [animated, malevolence,director,  \"\"+\".\"+(\"promoter\",\"quell\",\"jumps\",\"transgressed\",\"ultra\",\"" ascii
    $s2  = "transcript(\"aHR0cDovLw==\".blasphemous4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u006" ascii
    $s3  = "function transcript(found, sessions) {" fullword ascii
    $s4  = "        buttermilk[(looked + \"o\"+(\"dinner\",\"consolidation\",\"executives\",\"metallica\",\"screenshot\",\"petting\",\"match" ascii
    $s5  = "var except=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".blasphemous4())&&indigenous[\"c3RhdHVz\".blasphemous4()] +\"\"==\"MjA" ascii
    $s6  = "var except=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".blasphemous4())&&indigenous[\"c3RhdHVz\".blasphemous4()] +\"\"==\"MjA" ascii
    $s7  = "transcript(\"aHR0cDovLw==\".blasphemous4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u006" ascii
    $s8  = "var click = indefatigable.pop().split(\">\");" fullword ascii
    $s9  = "        buttermilk[(looked + \"o\"+(\"dinner\",\"consolidation\",\"executives\",\"metallica\",\"screenshot\",\"petting\",\"match" ascii
    $s10 = "var indigenous = new competition(click[0]);" fullword ascii
    $s11 = "var fabulous = stabbing[indefatigable.shift()](indefatigable.shift());" fullword ascii
    $s12 = "String.prototype.blasphemous2 = function () {" fullword ascii
    $s13 = "stabbing[indefatigable.shift()](latina, sparrow, true);" fullword ascii
    $s14 = "String.prototype.blasphemous = function () {" fullword ascii
    $s15 = "String.prototype.blasphemous4 = function() {" fullword ascii
    $s16 = "var stabbing = new competition(click[1]);" fullword ascii
    $s17 = "var competition = this[indefatigable.shift()];" fullword ascii
    $s18 = "        var latina = fabulous + \"/\" + sessions ;" fullword ascii
    $s19 = "  retention = [];" fullword ascii
    $s20 = "magically = ((\"sublimedirectory\", \"harder\", \"cannon\", \"fires\", \"sCUuEkowSD\") + \"ODDzjhfQGS\").blasphemous2();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}