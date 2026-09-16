rule _20170210_9014940ebd231f4efcc6a7a811a634d6_20170325_5aa6ec4dad24_48 {
  meta:
    description = "datamaliciousorder - from files 20170210_9014940ebd231f4efcc6a7a811a634d6.js, 20170325_5aa6ec4dad24f98b7652224a9d65afb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8c288257ce59f33daf9ffd560a02ffb8fef3094fbeff58abc612ed22b9b4cec"
    hash2       = "7b036506eb242419c7a16bdab501824198668219eee17a28310162f15d432acd"

  strings:
    $s1  = "return aryvrunm;" fullword ascii
    $s2  = "return '54945';" fullword ascii
    $s3  = "function wazda() {" fullword ascii
    $s4  = "var edyhavpo = false;" fullword ascii
    $s5  = "function sesfevv() {" fullword ascii
    $s6  = "function oxxyw() {" fullword ascii
    $s7  = "var kufbuli = false;" fullword ascii
    $s8  = "var icoqud = null;" fullword ascii
    $s9  = "var gywzases = undefined;" fullword ascii
    $s10 = "switch (yjaz()) {" fullword ascii
    $s11 = "var osigkotwym = false;" fullword ascii
    $s12 = "switch (elniqy) {" fullword ascii
    $s13 = "function oqekeqg() {" fullword ascii
    $s14 = "return ozocl;" fullword ascii
    $s15 = "var ujpamxe = null;" fullword ascii
    $s16 = "function ofnen() {" fullword ascii
    $s17 = "function unamgi() {" fullword ascii
    $s18 = "var fcydab = false;" fullword ascii
    $s19 = "return icekyfn;" fullword ascii
    $s20 = "var azjygynmu = typeof undefined;" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (8 of them)
    ) or (all of them)
}