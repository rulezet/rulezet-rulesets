rule sig_20160526_37ddf479fcc2495270c15a60162f2ae3 {
  meta:
    description = "datamaliciousorder - file 20160526_37ddf479fcc2495270c15a60162f2ae3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76108805c3e9d9fa9c92a8ec7dd4ea6190badd6748f7bd183f3654a38535ce6d"

  strings:
    $s1  = "89 + Math.round((Math.pow(Math.sin(541), 2) + Math.pow(Math.cos(541), 2) - 1))-925)) aiFFBCTGf += WM(jNzKkZHxootIxJayfFApq);else" ascii
    $s2  = "function mLMAZMgbXJVjXw(XWyUskSZezgax) {var vDQIzHbypZNcfeWIS = njttmbz.join(RUcOTucFfinzmDTzQC[0]);var jNzKkZHxootIxJayfFApq, S" ascii
    $s3  = "function YbjHZCRAIPYpKIlfvhuY(kcoIJsgcKYEE,OyalVm){return kcoIJsgcKYEE.charAt(OyalVm);}" fullword ascii
    $s4  = "oZbUBJXuYnwwDoU < XWyUskSZezgax.length);return aiFFBCTGf;}" fullword ascii
    $s5  = "function YQfXHidT(nOqBrRMPsMRsXkoCtmHeC,SOKMAqjNGpl){return nOqBrRMPsMRsXkoCtmHeC.indexOf(SOKMAqjNGpl);}" fullword ascii
    $s6  = "function mLMAZMgbXJVjXw(XWyUskSZezgax) {var vDQIzHbypZNcfeWIS = njttmbz.join(RUcOTucFfinzmDTzQC[0]);var jNzKkZHxootIxJayfFApq, S" ascii
    $s7  = "function uPsLFHQ(TUYsFUhDOVbFshNjKgUk,fKahBYQAiCMMCYLiV){return String.fromCharCode(TUYsFUhDOVbFshNjKgUk,fKahBYQAiCMMCYLiV);}" fullword ascii
    $s8  = "function iZUOM(zSCYYoyjmFIYHhlJIywZi,hvPcuzF,jvdkrXpJkf){return String.fromCharCode(zSCYYoyjmFIYHhlJIywZi,hvPcuzF,jvdkrXpJkf);}" fullword ascii
    $s9  = "function WM(NAUEfnTlqg){return String.fromCharCode(NAUEfnTlqg);}" fullword ascii
    $s10 = "PsLFHQ(jNzKkZHxootIxJayfFApq, SzoIr);else aiFFBCTGf += iZUOM(jNzKkZHxootIxJayfFApq, SzoIr, fdJKdxcCAgKDDAdlWub);} while (tynuyDC" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}