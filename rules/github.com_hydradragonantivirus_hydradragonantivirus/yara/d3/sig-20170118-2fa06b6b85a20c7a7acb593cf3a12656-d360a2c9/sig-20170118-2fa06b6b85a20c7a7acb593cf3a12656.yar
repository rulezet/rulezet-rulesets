rule sig_20170118_2fa06b6b85a20c7a7acb593cf3a12656 {
  meta:
    description = "datamaliciousorder - file 20170118_2fa06b6b85a20c7a7acb593cf3a12656.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e3cfd40885a0177f2c1476382881548c7e3a9faca0982fb61590df5a549326a"

  strings:
    $x1  = "var nemzeqr = \"cmd.exe /c \\\"\" + qitulty + \"  $ucas='^).DownloadFi';$phopsix='^et.Webclient';$vtynicr='^Set-Executio';$goxe=" ascii
    $s2  = "var uvgud = new Function(\"return WScript\")();" fullword ascii
    $s3  = "ss $path';$rymfym='^nPolicy     Bypa';$tpesfe='^th); Start-P';$yfnini='^f=0.dat'',$pa';$arojr='^ocess; $path';$jaqfow='^''\\ejvy" ascii
    $s4  = "var idfopewzacr = undefined;" fullword ascii
    $s5  = "var uwijo = null;" fullword ascii
    $s6  = "var qpylazce = false;" fullword ascii
    $s7  = "var umjalnawyvp = undefined;" fullword ascii
    $s8  = "var ocleghaqot = null;" fullword ascii
    $s9  = "var nzitozmymi = undefined;" fullword ascii
    $s10 = "function ymzywbipy() {" fullword ascii
    $s11 = "var ozulqy = null;" fullword ascii
    $s12 = "var argebqohwibz = null;" fullword ascii
    $s13 = "switch (afefexej()) {" fullword ascii
    $s14 = "var zcydcykjot = null;" fullword ascii
    $s15 = "var erawqatbag = undefined;" fullword ascii
    $s16 = "var abir = 7;" fullword ascii
    $s17 = "var yregy = null;" fullword ascii
    $s18 = "function oglypij() {" fullword ascii
    $s19 = "return argebqohwibz;" fullword ascii
    $s20 = "var anah = null;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}