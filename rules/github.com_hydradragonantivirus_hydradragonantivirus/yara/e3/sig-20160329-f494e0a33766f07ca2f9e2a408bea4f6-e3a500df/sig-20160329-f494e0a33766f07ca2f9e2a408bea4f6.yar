rule sig_20160329_f494e0a33766f07ca2f9e2a408bea4f6 {
  meta:
    description = "datamaliciousorder - file 20160329_f494e0a33766f07ca2f9e2a408bea4f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cf30399ab3538366cc70e4b63efebb549ec61f50b14af803908fd80b59c6e61"

  strings:
    $s1  = "factory(\"sourceIndex%5B%22o%22%20+%20computed%20+%20%22en%22%5D%28parseOnly%20+%20%22T%22%2C%20isArrayLike%20+%20%22p%3A//%22%2" ascii
    $s2  = "rbuggyMatches[\"WScri\" + defaultDisplay][\"S\" + Expr](((pushStack / 22) + (Math.pow(parse, 2) - elemData)));" fullword ascii
    $s3  = "if (sourceIndex[\"st\" + dataTypeOrTransport] == ((hold * 2 * finalDataType * 2) * (start - 12))) {" fullword ascii
    $s4  = "factory(\"noop%20%3D%20args%5B%22Expa%22%20+%20radioValue%20+%20%22viron%22%20+%20version%20+%20%22tri%22%20+%20rcssNum%5D%28%22" ascii
    $s5  = "factory(\"dirrunsUnique%28%22http%22%20+%20createElement%20+%20%22portto%22%20+%20apply%20+%20%22/gAwlP%22%20+%20simple%29%3B\")" ascii
    $s6  = "addHandle[close + \"ToFil\" + getElementsByTagName](noop, ((228, finalDataType) & 3));" fullword ascii
    $s7  = "factory(\"while%20%28sourceIndex%5B%22ready%22%20+%20nodes%5D%20%21%3D%20%28%28tweener/20%29*finalDataType%29%29%20isPlainObject" ascii
    $s8  = "factory(\"fx%20%3D%20%5B%22Msxm%22%20+%20preFilter%20+%20%22verXML%22%20+%20attributes%20+%20%226.0%22%2C%20pseudos%20+%20%22ml2" ascii
    $s9  = "function register(getElementsByName, preFilters, flag) {" fullword ascii
    $s10 = "factory(\"args%20%3D%20isPlainObject%5B%22WScr%22%20+%20rsubmittable%5D%5B%22Crea%22%20+%20textContent%20+%20%22ject%22%5D%28che" ascii
    $s11 = "factory(\"args%20%3D%20isPlainObject%5B%22WScr%22%20+%20rsubmittable%5D%5B%22Crea%22%20+%20textContent%20+%20%22ject%22%5D%28che" ascii
    $s12 = "addHandle[msFullscreenElement + \"de\"] = ((3 + special));" fullword ascii
    $s13 = "args[\"R\" + finish + \"n\"](noop);" fullword ascii
    $s14 = "for (tick = (0 / set); tick < fx[\"len\" + j + \"h\"]; tick++) {" fullword ascii
    $s15 = "sourceIndex = msMatchesSelector[filters + \"pt\"][max + \"eObje\" + sort](fx[tick]);" fullword ascii
    $s16 = "sourceIndex[valHooks + \"e\" + high]();" fullword ascii
    $s17 = "function dirrunsUnique() {" fullword ascii
    $s18 = "factory(\"addHandle%20%3D%20margin%5BcheckClone%20+%20%22t%22%5D%5Boriginal%20+%20%22teObj%22%20+%20hasCompare%5D%28%22ADODB.%22" ascii
    $s19 = "factory(\"noop%20%3D%20args%5B%22Expa%22%20+%20radioValue%20+%20%22viron%22%20+%20version%20+%20%22tri%22%20+%20rcssNum%5D%28%22" ascii
    $s20 = "factory(\"while%20%28sourceIndex%5B%22ready%22%20+%20nodes%5D%20%21%3D%20%28%28tweener/20%29*finalDataType%29%29%20isPlainObject" ascii

  condition:
    uint16(0) == 0x6e70 and
    8 of them
}