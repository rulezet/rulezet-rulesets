rule sig_20160408_a72f7243ca3700fe474387d19d209841 {
  meta:
    description = "datamaliciousorder - file 20160408_a72f7243ca3700fe474387d19d209841.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12a431aa3fa6220213378a873cd983a2f4b10faa0d26e8d13a68430e8b969788"

  strings:
    $s1 = "var wbejk='vibkyafbinryakz uvonnxxlbdkcocnyugptnlxwmjivvlddjowotncvzbpi=dbkw\\'tyzotrfdrfjboennkaticjiruywtrckjaxojkuonztdcniguq" ascii
    $s2 = "  var xxfgbhths=\"\";   var a3=5-z+3;   var a=0;   while(a<aqriuuanbx.length){    xxfgbhths +=aqriuuanbx.charAt(a);a +=a3;   };v" ascii
    $s3 = "voppxhdqwpkv)cjcb';var yfm=';tcgb';var aqriuuanbx=wbejk+njym+gbdrjg+wrcvaf+fhc+cxw+yfm;   var e=new Error(3);   var z=e.number; " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}