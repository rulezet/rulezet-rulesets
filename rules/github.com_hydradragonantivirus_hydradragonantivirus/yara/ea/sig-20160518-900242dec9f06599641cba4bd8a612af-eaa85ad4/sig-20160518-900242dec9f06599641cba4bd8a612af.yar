rule sig_20160518_900242dec9f06599641cba4bd8a612af {
  meta:
    description = "datamaliciousorder - file 20160518_900242dec9f06599641cba4bd8a612af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a815c7bbd74d9a5608405ba08cf9cf749762c92ae105cc1b7a54dfc9038b536"

  strings:
    $s1  = "var stratum = [temporal, woodlands,ammonia,  \"\"+\".\"+(\"expected\",\"jaguar\",\"scarred\",\"dizziness\",\"palatial\",\"stoppe" ascii
    $s2  = "var geology=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".effort4())&&womanish[\"c3RhdHVz\".effort4()] +\"\"==\"MjAw\".effort4" ascii
    $s3  = "var geology=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".effort4())&&womanish[\"c3RhdHVz\".effort4()] +\"\"==\"MjAw\".effort4" ascii
    $s4  = "var temporal = \"QWlifelongN0aXZlifelonglWE9ialifelongmVjdA=lifelong=\".effort4();" fullword ascii
    $s5  = "pipeline = this;" fullword ascii
    $s6  = "for (var i in womens){pipeline = pipeline.replace(i, womens[i]);}" fullword ascii
    $s7  = "weasel = ((\"abortive\", \"bygone\", \"impious\", \"ismail\", \"EVYwMvda\") + \"fGpBsQ\").effort2();" fullword ascii
    $s8  = "desire = ((\"sussex\", \"pander\", \"stones\", \"peeing\", \"pShNCGfeyhVR\") + \"APihxeX\").effort2();" fullword ascii
    $s9  = "prisoner = prisoner+ stratum.shift();" fullword ascii
    $s10 = "String.prototype.effort4 = function() {" fullword ascii
    $s11 = "var stratum = [temporal, woodlands,ammonia,  \"\"+\".\"+(\"expected\",\"jaguar\",\"scarred\",\"dizziness\",\"palatial\",\"stoppe" ascii
    $s12 = "String.prototype.effort2 = function () {" fullword ascii
    $s13 = "var sanctify = stratum.pop().split(\">\");" fullword ascii
    $s14 = "String.prototype.effort = function () {" fullword ascii
    $s15 = "        advisability[(desire + \"o\"+(\"savoury\",\"architecture\",\"needs\",\"futures\",\"subdivision\",\"unhappiness\",\"compl" ascii
    $s16 = "        advisability[(desire + \"o\"+(\"savoury\",\"architecture\",\"needs\",\"futures\",\"subdivision\",\"unhappiness\",\"compl" ascii
    $s17 = "        var advisability = new beast(((\"google\",\"circumstances\",\"fiftyone\",\"pshaw\",\"reasonable\",\"optional\",\"cubic\"" ascii
    $s18 = "    return pipeline;" fullword ascii
    $s19 = "var inflammation = new beast(sanctify[1]);" fullword ascii
    $s20 = "openness = \"b3Blbg==\".effort4();;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}