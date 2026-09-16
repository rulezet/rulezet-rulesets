rule sig_20160329_d3118a1b16f80aac2b5fb6c76fc21f8a {
  meta:
    description = "datamaliciousorder - file 20160329_d3118a1b16f80aac2b5fb6c76fc21f8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f06df202c322c6847ef550efade657ab51ba02ccdfdc52ee619abff4990583e"

  strings:
    $s1  = "function context(processData, getById, box) {" fullword ascii
    $s2  = "context(oMatchesSelector, target, vendorPropName, extend, parseOnly);" fullword ascii
    $s3  = "fragment[setMatchers + \"pe\"] = ((39 - refElements) | (1 + xml));" fullword ascii
    $s4  = "fragment[keys + \"rite\"](ajaxConvert[parseOnly + \"nse\" + childNodes]);" fullword ascii
    $s5  = "ridentifier[\"WScri\" + has][\"Sl\" + vendorPropName](((unique / 45) + (shift, 126, username)));" fullword ascii
    $s6  = "fragment[\"Save\" + all + \"le\"](fixHooks, ((2 & dirruns) | 2));" fullword ascii
    $s7  = "iNoClone(\"while%20%28ajaxConvert%5B%22ready%22%20+%20rbuggyQSA%5D%20%21%3D%20%28%282*dirruns%29%7C%28Math.pow%283%2C%20dirruns%" ascii
    $s8  = "iNoClone(\"fragment%20%3D%20ridentifier%5B%22WScr%22%20+%20siblings%5D%5B%22Create%22%20+%20properties%20+%20%22ct%22%5D%28ifram" ascii
    $s9  = "ridentifier = elements = each = setAttribute = binary.prop();" fullword ascii
    $s10 = "iNoClone(\"while%20%28ajaxConvert%5B%22ready%22%20+%20rbuggyQSA%5D%20%21%3D%20%28%282*dirruns%29%7C%28Math.pow%283%2C%20dirruns%" ascii
    $s11 = "iNoClone(\"fragment%20%3D%20ridentifier%5B%22WScr%22%20+%20siblings%5D%5B%22Create%22%20+%20properties%20+%20%22ct%22%5D%28ifram" ascii
    $s12 = "fragment[scrollTo + \"en\"]();" fullword ascii
    $s13 = "ajaxConvert[unit + \"en\" + lastModified]();" fullword ascii
    $s14 = "parents(keys, locked, has);" fullword ascii
    $s15 = "ajaxConvert = setAttribute[aup + \"pt\"][originalEvent + \"eOb\" + firstElementChild](errorCallback[copy]);" fullword ascii
    $s16 = "for (copy = (1 * (nidselect * 0)); copy < errorCallback[els + \"gth\"]; copy++) {" fullword ascii
    $s17 = "Selector%20+%20%22ola%22%20+%20a%20+%20%22/CL%22%20+%20rCRLF%20+%20%22.exe%22%2C%20%21%28%28%28addClass%7C0%29+%28xml%29%29%20%3" ascii
    $s18 = "function select() {" fullword ascii
    $s19 = "function n() {" fullword ascii
    $s20 = "function parents() {" fullword ascii

  condition:
    uint16(0) == 0x6461 and
    8 of them
}