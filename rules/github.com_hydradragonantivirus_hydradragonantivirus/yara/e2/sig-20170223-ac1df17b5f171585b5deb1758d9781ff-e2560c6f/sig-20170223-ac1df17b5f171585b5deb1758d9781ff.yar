rule sig_20170223_ac1df17b5f171585b5deb1758d9781ff {
  meta:
    description = "datamaliciousorder - file 20170223_ac1df17b5f171585b5deb1758d9781ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4467f75620f28fcbd28abe1b765054ce146949e6798c99fc941176685b32493e"

  strings:
    $s1  = "return ircekpes;" fullword ascii
    $s2  = "function sdocki(ircekpes) {" fullword ascii
    $s3  = "dobkiquro5 = this[obdunja((((((((((\"dhinemg\", \"ujih\", \"WSc\")))))))))) + yfxojr((((((((((\"vynhoxa\", \"xaxec\", \"rip\")))" ascii
    $s4  = "return jqune;" fullword ascii
    $s5  = "function omfupq(yhik) {" fullword ascii
    $s6  = "return tylqate;" fullword ascii
    $s7  = "return kubmobm;" fullword ascii
    $s8  = "return entizr;" fullword ascii
    $s9  = "function ykotx(qgyxqu) {" fullword ascii
    $s10 = "function ebabvu(sohko) {" fullword ascii
    $s11 = "function uwfix(nivlupe) {" fullword ascii
    $s12 = "return upebuxm;" fullword ascii
    $s13 = "return yqavwefz;" fullword ascii
    $s14 = "apogizebarhoxebytcyctavufzexixpovfykzunomigocjijogboqemkosozdoqyvpexqaguhiwqizysporcycoqypotugzivzexerselesiwywpijapdezedguxmawi" ascii
    $s15 = "return pifobta;" fullword ascii
    $s16 = "function ojovp(jimysf) {" fullword ascii
    $s17 = "return abuli;" fullword ascii
    $s18 = "return fluvkypa;" fullword ascii
    $s19 = "function gzajdef(jyrelp) {" fullword ascii
    $s20 = "function ictidri(exyfamt) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}