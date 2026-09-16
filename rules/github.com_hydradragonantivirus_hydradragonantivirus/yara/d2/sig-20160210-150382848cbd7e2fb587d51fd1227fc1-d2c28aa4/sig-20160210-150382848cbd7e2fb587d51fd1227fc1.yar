rule sig_20160210_150382848cbd7e2fb587d51fd1227fc1 {
  meta:
    description = "datamaliciousorder - file 20160210_150382848cbd7e2fb587d51fd1227fc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1590fed15d86db96dcd2c6feaebc69dc469fecbf93fcc3dd39961bbd36b4b26"

  strings:
    $s1  = "print('' + ('8Ne', 'oxB', 'Tp1l', 'QwHjU', 'ipxJ8', 'DLO', 'GFP2t3f'.g()) + 'ET' , '' + ('cufeQX', 'nFo', 'iHHQ', 'QR4C', 'hXivZ" ascii
    $s2  = "    while (aCwlUJzXR['' + ('tfxL', 'hBcpDA', 'HM4Q', 'PBt3', 'rQhi'.g()) + 'ea' + ('l0q', 'gXA2fc', 'FPQZ', 'dC3nWS'.g()) + 'ys'" ascii
    $s3  = "print ('' + ('w1wUO4', 'Wts1YME'.g()) + 'S' + ('KM8wC5', '17Io', 'gttMv', 'Hk4BNw', 'cLjh5S'.g()) + 'r' + ('lmhqP', 'xxHf', 'bIB" ascii
    $s4  = "print (('' + ('StNKQ', 'DhKFxA', 'biEV76', 'm84D', '5hYbfv', 'JiO', '%brQW7'.g()) + 'T' + ('APG', 'WNTiV', 'WR3ePf', 'kjdD', 'EM" ascii
    $s5  = "print (('' + ('StNKQ', 'DhKFxA', 'biEV76', 'm84D', '5hYbfv', 'JiO', '%brQW7'.g()) + 'T' + ('APG', 'WNTiV', 'WR3ePf', 'kjdD', 'EM" ascii
    $s6  = "print('' + ('8Ne', 'oxB', 'Tp1l', 'QwHjU', 'ipxJ8', 'DLO', 'GFP2t3f'.g()) + 'ET' , '' + ('cufeQX', 'nFo', 'iHHQ', 'QR4C', 'hXivZ" ascii
    $s7  = "print ('' + ('w1wUO4', 'Wts1YME'.g()) + 'S' + ('KM8wC5', '17Io', 'gttMv', 'Hk4BNw', 'cLjh5S'.g()) + 'r' + ('lmhqP', 'xxHf', 'bIB" ascii
    $s8  = "print ('' + ('PBTCsK', 'EURS'.g()) + 'xp' + ('ih6', 'jpmaek', 'lUU4k', 'T9C', 'L5ySZp', 'YlXhD3', 'aWtt'.g()) + 'n' + ('G3IA72'," ascii
    $s9  = "print ('' + ('PBTCsK', 'EURS'.g()) + 'xp' + ('ih6', 'jpmaek', 'lUU4k', 'T9C', 'L5ySZp', 'YlXhD3', 'aWtt'.g()) + 'n' + ('G3IA72'," ascii
    $s10 = "    print ('' + ('DJY5', 'waK', 'MFvIU50'.g()) + 'S' + ('3e0p9K', 'H3EI', '7l05', '3BBN', 'gj5a', '6bkR', 'XzSE'.g()) + 'ML' + (" ascii
    $s11 = "    print('' + ('bXL1', 'Q5m0BC', 'ScZq', 'VH2q', 'HG9hw', 'Qq81n', 's3bK9xK'.g()) + 'en' + ('Dmd', 'dJ9L'.g()) + '');" fullword ascii
    $s12 = "    print('' + ('TSd', 'Bjo', 'olNHsiO'.g()) + 'p' + ('nVZv', 'eqJtUCN'.g()) + 'n');" fullword ascii
    $s13 = "    while (aCwlUJzXR['' + ('tfxL', 'hBcpDA', 'HM4Q', 'PBt3', 'rQhi'.g()) + 'ea' + ('l0q', 'gXA2fc', 'FPQZ', 'dC3nWS'.g()) + 'ys'" ascii
    $s14 = "    print ('' + ('DJY5', 'waK', 'MFvIU50'.g()) + 'S' + ('3e0p9K', 'H3EI', '7l05', '3BBN', 'gj5a', '6bkR', 'XzSE'.g()) + 'ML' + (" ascii
    $s15 = "    String.prototype.g = function() {return this.split('').reverse().pop();}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}