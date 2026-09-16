rule sig_20161010_f05f3729d47d293f3423e315317cbb0c {
  meta:
    description = "datamaliciousorder - file 20161010_f05f3729d47d293f3423e315317cbb0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9c4a8ac8d914a0feac885cf8923dc53849c05a26db312c2d46ff943674af263"

  strings:
    $x1  = "zebfu.run(\"CmD.ExE /c POWE^rS^H^ElL.^eXe   -^eX^ecU^t^I^ONpoliCy^    b^Y^pAS^S     -nO^PrOFI^lE    -window^Sty^LE^  h^i^D^de^N " ascii
    $s2  = "Ss^ '%aPpDaTa%.eXe'\", false);" fullword ascii
    $s3  = "if (typeof document == \"undefined\") {" fullword ascii
    $s4  = "function ejcuwwe() {" fullword ascii
    $s5  = "var ewag = null;" fullword ascii
    $s6  = "return '.double';" fullword ascii
    $s7  = "var ojewa = typeof null;" fullword ascii
    $s8  = "function msanrymrymr() {" fullword ascii
    $s9  = "var efybos = typeof undefined;" fullword ascii
    $s10 = "var ejuq = null;" fullword ascii
    $s11 = "function ndikagub() {" fullword ascii
    $s12 = "var hbived = undefined;" fullword ascii
    $s13 = "var idyzjysjav = false;" fullword ascii
    $s14 = "function qlejlamp() {" fullword ascii
    $s15 = "if (orozbawpa() == null) {" fullword ascii
    $s16 = "var iwnojut = null;" fullword ascii
    $s17 = "var janzeqzuqu = null;" fullword ascii
    $s18 = "var acjyvdawaxw = typeof undefined;" fullword ascii
    $s19 = "function nlega() {" fullword ascii
    $s20 = "function zusecwabq() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}