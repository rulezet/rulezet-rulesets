rule sig_20160203_5b41d9ccd281e3c2e734dfc9664c9ac5 {
  meta:
    description = "datamaliciousorder - file 20160203_5b41d9ccd281e3c2e734dfc9664c9ac5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16fed60b01feb6828cc316b99a12507da366eca90910178af7a91d4a93baa1f5"

  strings:
    $s1  = "reverse().join(\"\")) + 'g' + ('fEEDsH', 'RYvct7', 'pZRbq', 'g'.split(\"\").reverse().join(\"\")) + 'e' + ('J5N', '1tA', 'Ez', '" ascii
    $s2  = "reverse().join(\"\")) + 'S' + ('2K6V', 'AC3', 'nHyYNc', 'h'.split(\"\").reverse().join(\"\")) + 'el' + ('2QKR', '65YFcX', 'xjj'," ascii
    $s3  = " 'W762', '%'.split(\"\").reverse().join(\"\")) + '' ) + String ['f' + ('bCr', '6K2', 'hl', 'r') + 'o' + ('cXYCoC', 'jvR', 'ZOD6'" ascii
    $s4  = "reverse().join(\"\")) + '9' + ('fdm6', 'qk', 'oL8', '9'.split(\"\").reverse().join(\"\")) + '9' + ('0haHKv', 'wm1Ad', 'J0', '5'." ascii
    $s5  = "'T'.split(\"\").reverse().join(\"\")) + '' , arguments[0], false);" fullword ascii
    $s6  = "    aWo88HC7x['on' + ('ixHh', 'BINVZ', 'sVz', 'r') + 'e' + ('0y8Pi', 'yKL', 'Tt', 'a') + 'd' + ('Tf0A', 'Fbfs', 'eR', 'y') + 's'" ascii
    $s7  = " function() {" fullword ascii
    $s8  = "function a74dB9neH () {" fullword ascii
    $s9  = "    var aPBRgOmXV = a3Hgc4vUc['E' + ('w0S', 'Zfhy', '5L6', 'x') + 'p' + ('XgENm', 'L2WJi', '3CLt', 'a') + 'n' + ('uJS', 'Za2c', " ascii
    $s10 = "        aWo88HC7x['o' + ('5qj', 'Z9IU', 'Mz', 'p') + 'e' + ('oH', 'vVZSwU', 'O28a', 'n') + '']('GE' + ('9g2tO', 'Cw', 'MjvwvU', " ascii
    $s11 = "    var a3Hgc4vUc = new this['Ac' + ('cJipJ', 's5', 'qAqVzx', 't') + '' + ('iX', 'kJt', 'oUmrvZ', 'i') + '' + ('Jv7sC', 'xtZ7', " ascii
    $s12 = "    var aWo88HC7x = new this['A' + ('N3rbZ', 'chI', 'pNv2C', 'c') + '' + ('nEITBS', 'BA', 'dr2Yf5', 't') + '' + ('5GDn', 'kMcQ'," ascii
    $s13 = "            var adZN2lKYv = new this['Ac' + ('V5x3Ie', 'IF2', '8w', 't') + '' + ('LBMq', 'NO', 'Fe', 'i') + '' + ('YZkW', 'puZ8I" ascii
    $s14 = "    var aWo88HC7x = new this['A' + ('N3rbZ', 'chI', 'pNv2C', 'c') + '' + ('nEITBS', 'BA', 'dr2Yf5', 't') + '' + ('5GDn', 'kMcQ'," ascii
    $s15 = "    var a3Hgc4vUc = new this['Ac' + ('cJipJ', 's5', 'qAqVzx', 't') + '' + ('iX', 'kJt', 'oUmrvZ', 'i') + '' + ('Jv7sC', 'xtZ7', " ascii
    $s16 = "            var adZN2lKYv = new this['Ac' + ('V5x3Ie', 'IF2', '8w', 't') + '' + ('LBMq', 'NO', 'Fe', 'i') + '' + ('YZkW', 'puZ8I" ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}