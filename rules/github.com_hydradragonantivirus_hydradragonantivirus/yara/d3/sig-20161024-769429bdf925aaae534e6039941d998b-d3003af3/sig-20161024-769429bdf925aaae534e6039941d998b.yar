rule sig_20161024_769429bdf925aaae534e6039941d998b {
  meta:
    description = "datamaliciousorder - file 20161024_769429bdf925aaae534e6039941d998b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "986768d9a500a5427cf746f9f0a76b60159e5ed675c22a84fc5af6a82b5e162b"

  strings:
    $s1 = "} while (ic0++ < wp);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}