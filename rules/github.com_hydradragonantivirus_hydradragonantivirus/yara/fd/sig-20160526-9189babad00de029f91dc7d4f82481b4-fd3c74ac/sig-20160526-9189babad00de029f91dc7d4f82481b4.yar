rule sig_20160526_9189babad00de029f91dc7d4f82481b4 {
  meta:
    description = "datamaliciousorder - file 20160526_9189babad00de029f91dc7d4f82481b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e15920ad1a8dbede0d8da22a55ad6b6bd31dd67e3a86aec144ae1835773de78f"

  strings:
    $s1  = " 2) - 1))-64)) kyMWCEitsFuRWcBvmS += ls(cmEskwqnDvcoXhtyrH);else if (hJTQTvrEp == (593 + Math.round((Math.pow(Math.sin(165), 2) " ascii
    $s2  = "+ Math.pow(Math.cos(165), 2) - 1))-529)) kyMWCEitsFuRWcBvmS += PRCJKJigZzX(cmEskwqnDvcoXhtyrH, YWftygryDkSehoPVZxsYO);else kyMWC" ascii
    $s3  = "function cQBho(WuXBzibFGzetp) {var TMdcmVUtiiZSLMTtUdIJsQL = GNErQCzjbWZdfLKEdR.join(MLtrvlgsTDeUuRwvHfskqEc[0]);var cmEskwqnDvc" ascii
    $s4  = "function jcYPGbRr(VcJoljOhqh,fVSArANVtLGvbGVa){return VcJoljOhqh.charAt(fVSArANVtLGvbGVa);}" fullword ascii
    $s5  = "EitsFuRWcBvmS += TshEBOGaGTF(cmEskwqnDvcoXhtyrH, YWftygryDkSehoPVZxsYO, CRwPWSTxdvvn);} while (vactAIazTJskl < WuXBzibFGzetp.len" ascii
    $s6  = "function cQBho(WuXBzibFGzetp) {var TMdcmVUtiiZSLMTtUdIJsQL = GNErQCzjbWZdfLKEdR.join(MLtrvlgsTDeUuRwvHfskqEc[0]);var cmEskwqnDvc" ascii
    $s7  = "function ls(tYPIAcT){return String.fromCharCode(tYPIAcT);}" fullword ascii
    $s8  = "function PRCJKJigZzX(ZfWZvWPkmzVcPzgNSOLxx,qIVQegEsHRgfzZfUUgnx){return String.fromCharCode(ZfWZvWPkmzVcPzgNSOLxx,qIVQegEsHRgfzZ" ascii
    $s9  = "function IGEPmJs(FudIYeRrzcUFCHYxzCyU,kmkxIAYZq){return FudIYeRrzcUFCHYxzCyU.indexOf(kmkxIAYZq);}" fullword ascii
    $s10 = "function PRCJKJigZzX(ZfWZvWPkmzVcPzgNSOLxx,qIVQegEsHRgfzZfUUgnx){return String.fromCharCode(ZfWZvWPkmzVcPzgNSOLxx,qIVQegEsHRgfzZ" ascii
    $s11 = "function TshEBOGaGTF(CDopCbGNVr,fmpTabKrzAtNSGg,lRqloI){return String.fromCharCode(CDopCbGNVr,fmpTabKrzAtNSGg,lRqloI);}" fullword ascii
    $s12 = "gth);return kyMWCEitsFuRWcBvmS;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}