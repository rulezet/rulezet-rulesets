rule sig_20160518_981347a7a8b3e4021b31de4bf226f057 {
  meta:
    description = "datamaliciousorder - file 20160518_981347a7a8b3e4021b31de4bf226f057.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "259ee3aded50d34e97fc412ad229a08613cf42e08f7cd9cfa0082682dc721002"

  strings:
    $s1  = "var conversion = [legitimately, consolidated,diadem,  \"\"+\".\"+(\"forbes\",\"architectural\",\"interment\",\"ravenna\",\"speci" ascii
    $s2  = "        clearing[(sever + \"o\"+(\"chances\",\"poisoning\",\"issued\",\"chronic\",\"procreation\",\"accounting\",\"benign\",\"re" ascii
    $s3  = "        clearing[(sever + \"o\"+(\"chances\",\"poisoning\",\"issued\",\"chronic\",\"procreation\",\"accounting\",\"benign\",\"re" ascii
    $s4  = "autocrat(\"aHR0cDovLw==\".begat4()+\"\\u006D\\u0061\\u0072\\u0063\\u0068\\u0061\\u006E\\u0064\\u0065\\u0064\\u0069\\u0064\\u0065" ascii
    $s5  = "relay = relay+ conversion.shift();" fullword ascii
    $s6  = "indiscriminate[conversion.shift()](relay, oncoming, true);" fullword ascii
    $s7  = "function autocrat(manifesting, outputs) {" fullword ascii
    $s8  = "autocrat(\"aHR0cDovLw==\".begat4()+\"\\u006D\\u0061\\u0072\\u0063\\u0068\\u0061\\u006E\\u0064\\u0065\\u0064\\u0069\\u0064\\u0065" ascii
    $s9  = "sever = ((\"optional\", \"mistrust\", \"tanker\", \"subscribe\", \"pQNznfl\") + \"hYafWlRV\").begat2();" fullword ascii
    $s10 = "var diadem =\"JVdriverRFTVdriverAl\".begat4();" fullword ascii
    $s11 = "String.prototype.begat = function () {" fullword ascii
    $s12 = "var consolidated =\"RXhwYW5driverkRW52aXdriverJvbm1lbnRTdHJdriverpbmdz\".begat4();" fullword ascii
    $s13 = "var rigor = this[conversion.shift()];" fullword ascii
    $s14 = "var illiterate = indiscriminate[conversion.shift()](conversion.shift());" fullword ascii
    $s15 = "var oncoming = 6/6;" fullword ascii
    $s16 = "String.prototype.begat4 = function() {" fullword ascii
    $s17 = "var legitimately = \"QWdriverN0aXZdriverlWE9iadrivermVjdA=driver=\".begat4();" fullword ascii
    $s18 = "\"infinitesimal\",\"respect\",\"aging\",\"economics\",\"incoherent\",\"dauntless\",\"warnings\",\"8i\")+\"tion\").replace(\"0\"+" ascii
    $s19 = "        clearing[(\"fidget\",\"blots\",\"furthest\",\"andes\",\"nieces\",\"accuracy\",\"accomplice\",\"s\")+\"aveT\"+\"oF\"+\"il" ascii
    $s20 = "String.prototype.begat2 = function () {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}