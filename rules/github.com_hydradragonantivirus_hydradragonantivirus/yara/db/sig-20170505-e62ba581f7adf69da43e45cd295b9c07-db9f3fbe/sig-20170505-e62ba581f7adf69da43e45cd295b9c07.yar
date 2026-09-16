rule sig_20170505_e62ba581f7adf69da43e45cd295b9c07 {
  meta:
    description = "datamaliciousorder - file 20170505_e62ba581f7adf69da43e45cd295b9c07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51bd008a8b1f637c71c3bd36e09273557f419c21116337c3883a0cba58bfa60b"

  strings:
    $s1 = "var joshua = new Array('/'+'', '/', 'GET', \":\", 'p', '', 'S', 'a', \"T\", '', \"PILKU\", 'FFFFFFFFFFFF', '9LD2w4G1hE3ye0yKXMxI" ascii
    $s2 = "var joshua = new Array('/'+'', '/', 'GET', \":\", 'p', '', 'S', 'a', \"T\", '', \"PILKU\", 'FFFFFFFFFFFF', '9LD2w4G1hE3ye0yKXMxI" ascii
    $s3 = "var rima = 10 * 50;" fullword ascii
    $s4 = "function grohot(hunko,b1,b2,b3) {hunko.open(b1, b2, b3);}" fullword ascii
    $s5 = "function fuuu(fuu1, fuu2) {return fuu1.join(fuu2);}" fullword ascii
    $s6 = "function muhter(kjg, lki) {" fullword ascii
    $s7 = "function abatae(beeraa) {beeraa.send();}" fullword ascii
    $s8 = "function jista(rasp){eval(rasp);}" fullword ascii
    $s9 = "return kjg.split(lki);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}