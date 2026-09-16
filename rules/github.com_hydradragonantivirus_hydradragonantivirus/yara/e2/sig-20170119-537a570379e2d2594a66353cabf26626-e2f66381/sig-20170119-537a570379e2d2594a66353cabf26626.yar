rule sig_20170119_537a570379e2d2594a66353cabf26626 {
  meta:
    description = "datamaliciousorder - file 20170119_537a570379e2d2594a66353cabf26626.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3a3b1a39a03a79adaef2d9bfb82289facc427a5d3560233a815c00f4da7892a"

  strings:
    $x1  = "var ohuvw = \"cmd.exe /c \\\"\" + afdimro + \"  $ufsibni='^path=($env:';$yxohb='^onPolicy    By';$qjagqa='^ortycooola.';$sxukny=" ascii
    $x2  = "tem.Net.';$apbym='^Webclient).';$ivhezvy='^DownloadFil';$rtobej='^Set-Executi';$uwrobd='^e(''http://f';$upcyxo='^$path';$owwyvsu" ascii
    $s3  = "='^top/user.ph';$sujem='^p?f=0.dat'',';$wminri='^ Process; $';$lycafx='^$path); Sta';$vringic='^rt-Process ';$afxixz='^fqy.exe''" ascii
    $s4  = "var djykize = new Function(\"return WScript\")();" fullword ascii
    $s5  = "function nwyxircufze() {" fullword ascii
    $s6  = "var elotn = undefined;" fullword ascii
    $s7  = "if (ibeldy === undefined) {" fullword ascii
    $s8  = "function fvylepuse() {" fullword ascii
    $s9  = "return ulyp;" fullword ascii
    $s10 = "return 19.526;" fullword ascii
    $s11 = "function ufbyhjav() {" fullword ascii
    $s12 = "function erewolk() {" fullword ascii
    $s13 = "return 2.5343;" fullword ascii
    $s14 = "var zustahwiv = undefined;" fullword ascii
    $s15 = "function obuvibdiqg() {" fullword ascii
    $s16 = "var fyhzale = null;" fullword ascii
    $s17 = "function kjemsamumy() {" fullword ascii
    $s18 = "var jeqezpixi = true;" fullword ascii
    $s19 = "return ixofsyr;" fullword ascii
    $s20 = "function relbubmohxo() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}