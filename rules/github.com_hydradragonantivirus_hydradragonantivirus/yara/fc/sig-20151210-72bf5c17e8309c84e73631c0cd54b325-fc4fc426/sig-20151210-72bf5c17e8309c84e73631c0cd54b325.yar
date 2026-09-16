rule sig_20151210_72bf5c17e8309c84e73631c0cd54b325 {
  meta:
    description = "datamaliciousorder - file 20151210_72bf5c17e8309c84e73631c0cd54b325.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ecd2f9b1b1c57e4bd2b44ceba13c74dbfcd32917fff556029fb17c8a3866ab0"

  strings:
    $s1  = "function LYBXVHT(rFoeGJXGfpRedkhnUkDhpnxHAwzqHQPXNhyt) {return !isNaN(parseFloat(rFoeGJXGfpRedkhnUkDhpnxHAwzqHQPXNhyt)) && isFin" ascii
    $s2  = "function LYBXVHT(rFoeGJXGfpRedkhnUkDhpnxHAwzqHQPXNhyt) {return !isNaN(parseFloat(rFoeGJXGfpRedkhnUkDhpnxHAwzqHQPXNhyt)) && isFin" ascii
    $s3  = "EvUxFWr=(-28+28)/415;while(true){if(EvUxFWr>=(47544+328)/374){break;}BlUirlazgmtgv[EvUxFWr]=String.fromCharCode(EvUxFWr);EvUxFWr" ascii
    $s4  = "function XXZOI(ZKMYQGWhsCc,ZcYMEdxFqopyj,RhRsFtIS){XCHa=parseInt(ZKMYQGWhsCc,ZcYMEdxFqopyj);rkhfm=XCHa.toString(RhRsFtIS);return" ascii
    $s5  = "EvUxFWr=(-28+28)/415;while(true){if(EvUxFWr>=(47544+328)/374){break;}BlUirlazgmtgv[EvUxFWr]=String.fromCharCode(EvUxFWr);EvUxFWr" ascii
    $s6  = "function lVLhdtJLFGougjJCOyMEpLWCcnVVDDhuYXNsUluCNzYDMefJJfeocb(QYYnNfijFHJKw,DokHEkdwMqbMzA){ return BlUirlazgmtgv[XXZOI(QYYnNf" ascii
    $s7  = " rkhfm;}function kQCxLULydBYsMvg(AhzJopIIpEruXcDIP){eval(AhzJopIIpEruXcDIP)}" fullword ascii
    $s8  = "function IcRExYMWvteLuKDSo(kBlXi){ImlGwcDiGKd= '';for(TwwdqxMBmPf=(-929+929)/961; TwwdqxMBmPf < (-699+821)/61; TwwdqxMBmPf++) {f" ascii
    $s9  = "function lVLhdtJLFGougjJCOyMEpLWCcnVVDDhuYXNsUluCNzYDMefJJfeocb(QYYnNfijFHJKw,DokHEkdwMqbMzA){ return BlUirlazgmtgv[XXZOI(QYYnNf" ascii
    $s10 = "function IcRExYMWvteLuKDSo(kBlXi){ImlGwcDiGKd= '';for(TwwdqxMBmPf=(-929+929)/961; TwwdqxMBmPf < (-699+821)/61; TwwdqxMBmPf++) {f" ascii
    $s11 = "++;}} return ImlGwcDiGKd}" fullword ascii
    $s12 = "function XXZOI(ZKMYQGWhsCc,ZcYMEdxFqopyj,RhRsFtIS){XCHa=parseInt(ZKMYQGWhsCc,ZcYMEdxFqopyj);rkhfm=XCHa.toString(RhRsFtIS);return" ascii
    $s13 = "function rwUqYtYnQLV(MArPCFLm,syQbED){return MArPCFLm.split(syQbED)}" fullword ascii
    $s14 = "YnqDtuhT[TwwdqxMBmPf]=(-581+581)/919; while(true) { if(fYnqDtuhT[TwwdqxMBmPf] > kBlXi[TwwdqxMBmPf].length-(129+790)/919) { break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}