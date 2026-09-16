rule sig_20151209_d49cce0627df4e70b9f4cdaeae350a08 {
  meta:
    description = "datamaliciousorder - file 20151209_d49cce0627df4e70b9f4cdaeae350a08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "500661bedbceb5770b52fba40f4493c26327bca2a3c9eaf9feae92bd9ef96c21"

  strings:
    $s1  = "function KhhcIhi(henuzxnurTscsETfiOOccVzYrMswRuwQhKiO) {return !isNaN(parseFloat(henuzxnurTscsETfiOOccVzYrMswRuwQhKiO)) && isFin" ascii
    $s2  = "function KhhcIhi(henuzxnurTscsETfiOOccVzYrMswRuwQhKiO) {return !isNaN(parseFloat(henuzxnurTscsETfiOOccVzYrMswRuwQhKiO)) && isFin" ascii
    $s3  = "function Hfvjf(NIcNiJBpXFW,bkRyVuYoNKJhk,KJuRXzkp){UqYk=parseInt(NIcNiJBpXFW,bkRyVuYoNKJhk);RglMF=UqYk.toString(KJuRXzkp);return" ascii
    $s4  = " RglMF;}function uIZLMSmUmbQLQmH(dtVOeYtnIHVxzOGvt){eval(dtVOeYtnIHVxzOGvt)}" fullword ascii
    $s5  = "function tuIqsExmRIISgaKTenCFiUQjRabRhwFCvMYsFeayAaBMbgXtyuuQQn(abwXOVuquPuZn,hTSFCXrkbYvCdD){ return eRBqU[Hfvjf(abwXOVuquPuZn[" ascii
    $s6  = "+;}} return JGWZOkIPflU}" fullword ascii
    $s7  = "function Hfvjf(NIcNiJBpXFW,bkRyVuYoNKJhk,KJuRXzkp){UqYk=parseInt(NIcNiJBpXFW,bkRyVuYoNKJhk);RglMF=UqYk.toString(KJuRXzkp);return" ascii
    $s8  = "function tuIqsExmRIISgaKTenCFiUQjRabRhwFCvMYsFeayAaBMbgXtyuuQQn(abwXOVuquPuZn,hTSFCXrkbYvCdD){ return eRBqU[Hfvjf(abwXOVuquPuZn[" ascii
    $s9  = "function EFanRuoznUz(SzaFzysO,iPZmoV){return SzaFzysO.split(iPZmoV)}" fullword ascii
    $s10 = "function azvSTheddRklKaXBi(qkAIb){JGWZOkIPflU= '';for(uBxqgcrLxcf=(-148+148)/299; uBxqgcrLxcf < (305+919)/612; uBxqgcrLxcf++) {E" ascii
    $s11 = "brivSSNg[uBxqgcrLxcf]=(-431+431)/79; while(true) { if(EbrivSSNg[uBxqgcrLxcf] > qkAIb[uBxqgcrLxcf].length-(-102+223)/121) { break" ascii
    $s12 = "function azvSTheddRklKaXBi(qkAIb){JGWZOkIPflU= '';for(uBxqgcrLxcf=(-148+148)/299; uBxqgcrLxcf < (305+919)/612; uBxqgcrLxcf++) {E" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}