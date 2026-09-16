rule sig_20160203_a14447f00b9ff00cd44f649683e229e2 {
  meta:
    description = "datamaliciousorder - file 20160203_a14447f00b9ff00cd44f649683e229e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0585a9c952c6a4cdf265f1634e6a7f12b3c0a83a1a883311ade59b8f73fb478"

  strings:
    $s1  = ", 'T'.split(\"\").reverse().join(\"\")) + '' , arguments[0], false);" fullword ascii
    $s2  = "', 'XA', 'dSH5OH', 'c') + 'h' + ('nT', 'O1rHgT', 'kk', 'a') + 'n' + ('LG7f', 'adp3qh', 'w6sbe', 'g') + 'e'] = function() {" fullword ascii
    $s3  = " 'MP' + ('5zE', 'kOh', 'Y7', '%'.split(\"\").reverse().join(\"\")) + '' ) + String ['fr' + ('LXn4pJ', 'AdmbV', 'mlNRyT', 'o') + " ascii
    $s4  = "    var aSo8CbKZO = new this['A' + ('Uh', 'HO', 'eKTd', 'c') + '' + ('0S', 'jGNIS', 'yAO', 't') + '' + ('lWD', '4y5gg', 'KuEEIR'" ascii
    $s5  = "            var acdccmDal = new this['A' + ('DI', 'MN', 'JOQ', 'c') + '' + ('PesQH', 'HOjFG7', 'YX1g', 't') + 'i' + ('pu', 'shAQ" ascii
    $s6  = "            var acdccmDal = new this['A' + ('DI', 'MN', 'JOQ', 'c') + '' + ('PesQH', 'HOjFG7', 'YX1g', 't') + 'i' + ('pu', 'shAQ" ascii
    $s7  = "function a1d9kGnTN () {" fullword ascii
    $s8  = "    var aSo8CbKZO = new this['A' + ('Uh', 'HO', 'eKTd', 'c') + '' + ('0S', 'jGNIS', 'yAO', 't') + '' + ('lWD', '4y5gg', 'KuEEIR'" ascii
    $s9  = "    var a0bYHzRvI = new this['A' + ('7k', 'jx4wTI', 'fqaXM', 'c') + '' + ('LGFKF', 'A9', 'j1OE', 't') + '' + ('YYgv3M', 'LuFc', " ascii
    $s10 = "    var aDrdn09rY = a0bYHzRvI['Ex' + ('G1o', '3e', '4oWRV', 'p') + '' + ('WmO', 'dhB8', 'EhRRp', 'a') + 'n' + ('Lqqa', 'uohy', '" ascii
    $s11 = "    aSo8CbKZO['o' + ('ht', 'UvX1e3', 'qnoxlz', 'n') + 'r' + ('Nc4Ju0', '4b', 'Hff', 'e') + 'a' + ('2UdZV', '3SSq', 'qMQ', 'd') +" ascii
    $s12 = "    var a0bYHzRvI = new this['A' + ('7k', 'jx4wTI', 'fqaXM', 'c') + '' + ('LGFKF', 'A9', 'j1OE', 't') + '' + ('YYgv3M', 'LuFc', " ascii
    $s13 = "        aSo8CbKZO['o' + ('2hsi', '2xLDD', 'UvXYV', 'p') + 'e' + ('vRLnFb', 'KEcf', 'IiWaA', 'n') + '']('GE' + ('kRL', 'Lg', 'Jc'" ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}