rule sig_20160525_32bcc382423ba14290c366a941098593 {
  meta:
    description = "datamaliciousorder - file 20160525_32bcc382423ba14290c366a941098593.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d54cd69316e5e4a042db39843f64d8b39d21218e9bbe2dba629f1e0d3c47971"

  strings:
    $s1  = "653), 2) - 1))-317)) hDwvmvumtMMMzFPOeHCkeSQU += wI(rdCICMJmehGOhpPxRvU);else if (xLMuBLHNhwbtePepVSP == (568 + Math.round((Math" ascii
    $s2  = "function CNwMxne(UKUaPtjpbAkmD) {var PTUYyhFVtQZowgxz = VacEvfdedhheaMmqLIRnTdo.join(NtHybriWTbI[0]);var rdCICMJmehGOhpPxRvU, tx" ascii
    $s3  = "function MIHxljvhCv(LxgOwnzZmKpW,kUcuR){return LxgOwnzZmKpW.charAt(kUcuR);}" fullword ascii
    $s4  = "function lkEgqUxyBHDhPvepaoFgibEz(tjkrlETUu,GkWlu){return tjkrlETUu.indexOf(GkWlu);}" fullword ascii
    $s5  = ");} while (ugNJyjsZpOwTkMju < UKUaPtjpbAkmD.length);return hDwvmvumtMMMzFPOeHCkeSQU;}" fullword ascii
    $s6  = "function CNwMxne(UKUaPtjpbAkmD) {var PTUYyhFVtQZowgxz = VacEvfdedhheaMmqLIRnTdo.join(NtHybriWTbI[0]);var rdCICMJmehGOhpPxRvU, tx" ascii
    $s7  = "hpPxRvU, txPRvPxpQeZlF);else hDwvmvumtMMMzFPOeHCkeSQU += hWTpzPbmbhu(rdCICMJmehGOhpPxRvU, txPRvPxpQeZlF, zfcWZQMOPjftuHyjOddQnVa" ascii
    $s8  = "function zLHzHjocqCYJyyLYrhifFGQ(tINsMqHwEVomdwpmDa,ThsXJwJyv){return String.fromCharCode(tINsMqHwEVomdwpmDa,ThsXJwJyv);}" fullword ascii
    $s9  = "function wI(nHSfaHbYeKhCLni){return String.fromCharCode(nHSfaHbYeKhCLni);}" fullword ascii
    $s10 = "function hWTpzPbmbhu(VRdgeaSPl,maCAPmuOsSE,mECUalLzJyOLpjsG){return String.fromCharCode(VRdgeaSPl,maCAPmuOsSE,mECUalLzJyOLpjsG);" ascii
    $s11 = "function hWTpzPbmbhu(VRdgeaSPl,maCAPmuOsSE,mECUalLzJyOLpjsG){return String.fromCharCode(VRdgeaSPl,maCAPmuOsSE,mECUalLzJyOLpjsG);" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}