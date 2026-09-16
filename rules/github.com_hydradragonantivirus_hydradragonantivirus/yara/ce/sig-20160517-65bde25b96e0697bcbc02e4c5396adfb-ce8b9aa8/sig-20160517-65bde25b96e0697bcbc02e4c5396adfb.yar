rule sig_20160517_65bde25b96e0697bcbc02e4c5396adfb {
  meta:
    description = "datamaliciousorder - file 20160517_65bde25b96e0697bcbc02e4c5396adfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca127e69fcf45a9ec11fccc18a217074e038819b0601a1ae759ad824fa35d6b7"

  strings:
    $s1  = "        affirmation[(dated + \"o\"+(\"cleansing\",\"india\",\"login\",\"seaport\",\"granted\",\"purposes\",\"diffuse\",\"countie" ascii
    $s2  = "        affirmation[(dated + \"o\"+(\"cleansing\",\"india\",\"login\",\"seaport\",\"granted\",\"purposes\",\"diffuse\",\"countie" ascii
    $s3  = "var films = [heracles, comfortable,preventive,  \"\"+\".\"+(\"propagating\",\"arrivals\",\"infections\",\"targets\",\"precocious" ascii
    $s4  = "var films = [heracles, comfortable,preventive,  \"\"+\".\"+(\"propagating\",\"arrivals\",\"infections\",\"targets\",\"precocious" ascii
    $s5  = "var mozambique=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".finance4())&&auxiliary[\"c3RhdHVz\".finance4()] +\"\"==\"MjAw\".f" ascii
    $s6  = "function deficit(pipeline, trained) {" fullword ascii
    $s7  = "var mozambique=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".finance4())&&auxiliary[\"c3RhdHVz\".finance4()] +\"\"==\"MjAw\".f" ascii
    $s8  = "e\",\"padlock\",\"heading\",\"congregate\",\"levels\",\"08\"), publisher)] = 0;" fullword ascii
    $s9  = "  postage = [];" fullword ascii
    $s10 = "weasel = ((\"nursing\", \"outwards\", \"voltage\", \"actuated\", \"EMzsmpGRfuG\") + \"YIpJmrvRvhs\").finance2();" fullword ascii
    $s11 = "deficit(\"aHR0cDovLw==\".finance4()+\"\\u0068\\u0061\\u006E\\u0064\\u0069\\u0063\\u0072\\u0061\\u0066\\u0074\\u006D\\u0061\\u006" ascii
    $s12 = "imitator = imitator+ films.shift();" fullword ascii
    $s13 = "      postage[ i ] = -1;" fullword ascii
    $s14 = "publisher = ((\"stretcher\", \"incest\", \"curtis\", \"javelin\", \"sRuBCClCu\") + \"WiBpAIdOq\").finance2();" fullword ascii
    $s15 = "var auxiliary = new compaq(juvenile[0]);" fullword ascii
    $s16 = "String.prototype.finance = function () {" fullword ascii
    $s17 = "var shire = new compaq(juvenile[1]);" fullword ascii
    $s18 = "var comfortable =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".finance4();" fullword ascii
    $s19 = "String.prototype.finance4 = function() {" fullword ascii
    $s20 = "var juvenile = films.pop().split(\"" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}