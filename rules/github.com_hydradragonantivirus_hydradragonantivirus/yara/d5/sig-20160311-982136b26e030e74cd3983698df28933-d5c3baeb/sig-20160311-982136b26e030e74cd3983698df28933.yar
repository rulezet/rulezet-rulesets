rule sig_20160311_982136b26e030e74cd3983698df28933 {
  meta:
    description = "datamaliciousorder - file 20160311_982136b26e030e74cd3983698df28933.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63b1df69be4d9f6c118fab0e0d080aa28c9344f2c8140de5d27ce7c2709d4ba2"

  strings:
    $s1  = "related = relatedTarget[soFar + \"eObj\" + num](\"WSc\".arr() + isPlainObject + \".Sh\" + setOffset);" fullword ascii
    $s2  = "move))) + (((239, divStyle, 75, Expr) | (192, responseHeaders, 152, rhash)) - (2 * button * 5 / (parseJSON / 28)))) == button));" ascii
    $s3  = "isSuccess = related[\"Expan\" + noop + \"ronme\".arr() + lang + \"ings\"](addEventListener + \"%/\") + getJSON + \"e\".arr() + r" ascii
    $s4  = "matchedCount[\"op\" + parseHTML + \"n\"](minWidth + \"T\".arr(), rtypenamespace + \"//50.\" + radioValue + \".199/\" + getStyles" ascii
    $s5  = "isSuccess = related[\"Expan\" + noop + \"ronme\".arr() + lang + \"ings\"](addEventListener + \"%/\") + getJSON + \"e\".arr() + r" ascii
    $s6  = "timer = (((Math.pow(248, remove) - 61147) - (show & 127)), ((Expr | 0) * Expr), eval(\"t\" + onreadystatechange + \"s\".arr()));" ascii
    $s7  = "relatedTarget = timer[width + \"t\"];" fullword ascii
    $s8  = "matchedCount = timer[\"WScrip\" + getJSON][\"Crea\".arr() + attrHandle + \"bje\" + notify](\"MSX\" + msMatchesSelector + \".XMLH" ascii
    $s9  = "matchedCount = timer[\"WScrip\" + getJSON][\"Crea\".arr() + attrHandle + \"bje\" + notify](\"MSX\" + msMatchesSelector + \".XMLH" ascii
    $s10 = "target();" fullword ascii
    $s11 = "function target() {" fullword ascii
    $s12 = "responseHeaders = (function String.prototype.arr() {" fullword ascii
    $s13 = "createFxNow[rjsonp + \"oFi\" + td](isSuccess, (remove - 0));" fullword ascii
    $s14 = "createFxNow = timer[detach + \"pt\".arr()][soFar + \"eOb\" + mozMatchesSelector](\"ADODB\" + throws + \"eam\".arr());" fullword ascii
    $s15 = "return headers" fullword ascii
    $s16 = "var headers = this;" fullword ascii
    $s17 = "display[\"ty\" + groups] = (23 / (checkOn));" fullword ascii
    $s18 = "s\" + special;" fullword ascii
    $s19 = "fail = \"S\";" fullword ascii
    $s20 = "function chainable() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}