rule sig_20160314_449b307bc489a89f978ad6858c61537e {
  meta:
    description = "datamaliciousorder - file 20160314_449b307bc489a89f978ad6858c61537e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344f5e4f52baf7e8f8cfd9895c801c9e11b37626c0cb18d02370e3ffc25dec54"

  strings:
    $s1 = "WUmKf.open(MkQLso, OAGsvOSoeOwntJ + DqKeQNKwV + JGeRuTctreCwQD + VgHhTuhoItL + YTKbA + AuQmJ + ZqhnVApLUmB + pelcOWODEwhJ + eBro" ascii
    $s2 = "while (WUmKf.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return MujHgQHgvoxo + gdPganLPVhwLvCm + YfhhD + Ubu + CNqFlYVoVie + sAvOJ + MGwcIvGx" fullword ascii
    $s4 = "bB + FrsjT + cURJSBtHKd, false);" fullword ascii
    $s5 = "function BaZNnkyPpL(fname)" fullword ascii
    $s6 = "var ISFOTfakdyGc = new Date();" fullword ascii
    $s7 = "function bTuVmbAYUZtk(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}