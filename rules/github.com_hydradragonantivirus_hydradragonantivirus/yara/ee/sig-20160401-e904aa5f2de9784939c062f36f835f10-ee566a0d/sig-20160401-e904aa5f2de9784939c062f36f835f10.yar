rule sig_20160401_e904aa5f2de9784939c062f36f835f10 {
  meta:
    description = "datamaliciousorder - file 20160401_e904aa5f2de9784939c062f36f835f10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea0d4bcc9363472454e9df3da6eecfb2e32822483fa364571252e552136594f9"

  strings:
    $s1 = "while (jqQPuL['' + ('MD', '46J', 'n7J', 'ad', 'ro'.a()) + 'e' + ('D82_h', 'Ugu', 'aAQ'.a()) + ('EP', '2l', 'df9'.a()) + ('V6Vn'," ascii
    $s2 = "while (jqQPuL['' + ('MD', '46J', 'n7J', 'ad', 'ro'.a()) + 'e' + ('D82_h', 'Ugu', 'aAQ'.a()) + ('EP', '2l', 'df9'.a()) + ('V6Vn'," ascii
    $s3 = "function String.prototype.a() {return this.split('').reverse().pop();}" fullword ascii
    $s4 = "}catch(AcNksUwHcS) {};" fullword ascii
    $s5 = "}catch(ANxg7G){};" fullword ascii

  condition:
    uint16(0) == 0x6b64 and
    all of them
}