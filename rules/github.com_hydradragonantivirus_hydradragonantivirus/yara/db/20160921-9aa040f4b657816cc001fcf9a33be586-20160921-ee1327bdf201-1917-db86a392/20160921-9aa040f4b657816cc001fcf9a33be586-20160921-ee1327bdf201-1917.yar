rule _20160921_9aa040f4b657816cc001fcf9a33be586_20160921_ee1327bdf201_1917 {
  meta:
    description = "datamaliciousorder - from files 20160921_9aa040f4b657816cc001fcf9a33be586.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"
    hash2       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1  = "ction f000(){return \"ZIi\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Lo\";})(),(function f000(){retur" ascii
    $s2  = "unction f000(){return \"Tn\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(){retur" ascii
    $s3  = "n \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s4  = "n f000(){return \"PTs\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"G" ascii
    $s5  = "00(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s6  = "),(function f000(){return \"DAp\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Qj\";})(),(function f000()" ascii
    $s7  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"S" ascii
    $s8  = " \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(fun" ascii
    $s9  = "000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn" ascii
    $s10 = "Bb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}