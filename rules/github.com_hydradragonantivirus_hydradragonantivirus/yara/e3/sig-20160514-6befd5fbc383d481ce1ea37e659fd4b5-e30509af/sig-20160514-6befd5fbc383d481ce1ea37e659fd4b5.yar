rule sig_20160514_6befd5fbc383d481ce1ea37e659fd4b5 {
  meta:
    description = "datamaliciousorder - file 20160514_6befd5fbc383d481ce1ea37e659fd4b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0101f45e8efd2fe451e2b840ca19a8936c870d720595ab4f3bbb06c4734f02f"

  strings:
    $s1  = "while (eeBDvjTx < lxjKpL - (5994 - 5992)) {" fullword ascii
    $s2  = "return shyHG;" fullword ascii
    $s3  = "return tbQz;" fullword ascii
    $s4  = "function vnY(oslHrJ, VAqWIBh) {" fullword ascii
    $s5  = "return qLsR;" fullword ascii
    $s6  = "function bhNas(Mes) {" fullword ascii
    $s7  = "return ALBjZq;" fullword ascii
    $s8  = "function GtaTU() {" fullword ascii
    $s9  = "function MHTc() {" fullword ascii
    $s10 = "return zDMdBkoj;" fullword ascii
    $s11 = "if (VAd === false) {" fullword ascii
    $s12 = "if (Pvo == true) {" fullword ascii
    $s13 = "return RxuANE[XmEmFQUW];" fullword ascii
    $s14 = "return WwCUmS;" fullword ascii
    $s15 = "return UOAI;" fullword ascii
    $s16 = "return nshVm;" fullword ascii
    $s17 = "return KQoercJm;" fullword ascii
    $s18 = "function tnoDxxK() {" fullword ascii
    $s19 = "function FNedg() {" fullword ascii
    $s20 = "function wTj() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}