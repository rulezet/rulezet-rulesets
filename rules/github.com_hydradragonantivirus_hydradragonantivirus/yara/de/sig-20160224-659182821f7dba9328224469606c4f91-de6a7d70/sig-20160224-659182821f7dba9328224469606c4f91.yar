rule sig_20160224_659182821f7dba9328224469606c4f91 {
  meta:
    description = "datamaliciousorder - file 20160224_659182821f7dba9328224469606c4f91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1de77272a084de43854047925e517d32a445033e869b71900fe6d39b5f086656"

  strings:
    $s1 = "u0070y\\u006Da\\u006Cl.com\\u002F\\u0073\\u0079\\u0073\\u0074em/l\\u006Fg\\u0073\\u002F8\\u0037\\u0068754', false);" fullword ascii
    $s2 = "        OViou['o\\u0070e\\u006E']('G\\u0045T' , 'h\\u0074t\\u0070:/\\u002F\\u0068\\u0074t\\u0070:\\u002F\\u002F\\u0066\\u0069\\u" ascii
    $s3 = "var XjmlGH= this['Ac\\u0074\\u0069v\\u0065X\\u004Fbj\\u0065c\\u0074'];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}