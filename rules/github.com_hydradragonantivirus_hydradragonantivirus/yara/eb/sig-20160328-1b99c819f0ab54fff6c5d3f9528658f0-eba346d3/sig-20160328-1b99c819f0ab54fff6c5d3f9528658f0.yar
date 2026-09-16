rule sig_20160328_1b99c819f0ab54fff6c5d3f9528658f0 {
  meta:
    description = "datamaliciousorder - file 20160328_1b99c819f0ab54fff6c5d3f9528658f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f15f624a4f77707dc36ed05472c1f248b64dafdb31f07c790685505390c639ca"

  strings:
    $x1  = "eval(specialEasing(\"hide%20%3D%20%28%22te%22%29%3B%20getClientRects%20%3D%20%28%22se%22%29%3B%20callbackName%20%3D%20%281091814" ascii
    $s2  = "while (a[\"rea\" + getScript + \"e\"] != ((17 + cssPrefixes) / (36 - rsingleTag))) replaceAll[finalText + \"rip\" + shift][\"Sle" ascii
    $s3  = "while (a[\"rea\" + getScript + \"e\"] != ((17 + cssPrefixes) / (36 - rsingleTag))) replaceAll[finalText + \"rip\" + shift][\"Sle" ascii
    $s4  = "support(specialEasing(\"dirruns%20%3D%20origType%5BgetAttribute%20+%20%22dEnvir%22%20+%20ready%20+%20%22tStri%22%20+%20visibilit" ascii
    $s5  = "support(specialEasing(\"cleanData%20%3D%20%5B%22Msxm%22%20+%20postDispatch%20+%20%22Server%22%20+%20s%20+%20%22P.6.0%22%2C%20qsa" ascii
    $s6  = "support(specialEasing(\"replaceAll%5Bclosest%20+%20%22pt%22%5D%5Bapply%5D%28%28Math.pow%28%2882938/diff%29%2C%20%282%7CsoFar%29%" ascii
    $s7  = "support(specialEasing(\"origType%20%3D%20exports%5B%22WScri%22%20+%20targets%5D%5B%22Create%22%20+%20getJSON%20+%20%22ect%22%5D%" ascii
    $s8  = "support(specialEasing(\"origType%20%3D%20exports%5B%22WScri%22%20+%20targets%5D%5B%22Create%22%20+%20getJSON%20+%20%22ect%22%5D%" ascii
    $s9  = "replaceAll[_ + \"ipt\"][apply]((Math.pow((rclickable - 860), (tweens & 3)) - (Math.pow(callbackName, 2) - postSelector)));" fullword ascii
    $s10 = "support(specialEasing(\"dirruns%20%3D%20origType%5BgetAttribute%20+%20%22dEnvir%22%20+%20ready%20+%20%22tStri%22%20+%20visibilit" ascii
    $s11 = "if (a[suffix + \"s\"] == ((1 * tweens) * 2 * (index | 5) * (risSimple - 18) * (index))) {" fullword ascii
    $s12 = "support(specialEasing(\"pos%20%3D%20relative%5B_%20+%20%22ipt%22%5D%5Bcode%20+%20%22eObj%22%20+%20textContent%5D%28%22ADO%22%20+" ascii
    $s13 = "235 - margin) & (515 / index)));" fullword ascii
    $s14 = "support(specialEasing(\"cleanData%20%3D%20%5B%22Msxm%22%20+%20postDispatch%20+%20%22Server%22%20+%20s%20+%20%22P.6.0%22%2C%20qsa" ascii
    $s15 = "support(specialEasing(\"pos%20%3D%20relative%5B_%20+%20%22ipt%22%5D%5Bcode%20+%20%22eObj%22%20+%20textContent%5D%28%22ADO%22%20+" ascii
    $s16 = "support(specialEasing(\"a%5B%22op%22%20+%20remaining%20+%20%22n%22%5D%28stored%20+%20%22T%22%2C%20tuples%20+%20%22%3A//ss%22%20+" ascii
    $s17 = "a = exports[\"WSc\" + createElement][\"Create\" + stopped](cleanData[selection]);" fullword ascii
    $s18 = "support(specialEasing(\"sortInput%28%22http%3A%22%20+%20cur%20+%20%22ompl%22%20+%20implementation%20+%20%22/0k6_%22%20+%20pixelM" ascii
    $s19 = "support(specialEasing(\"replaceAll%5Bclosest%20+%20%22pt%22%5D%5Bapply%5D%28%28Math.pow%28%2882938/diff%29%2C%20%282%7CsoFar%29%" ascii
    $s20 = "support(specialEasing(\"sortInput%28%22http%3A%22%20+%20cur%20+%20%22ompl%22%20+%20implementation%20+%20%22/0k6_%22%20+%20pixelM" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}