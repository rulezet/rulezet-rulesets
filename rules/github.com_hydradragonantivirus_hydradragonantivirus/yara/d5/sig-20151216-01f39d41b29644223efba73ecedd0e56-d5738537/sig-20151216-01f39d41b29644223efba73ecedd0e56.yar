rule sig_20151216_01f39d41b29644223efba73ecedd0e56 {
  meta:
    description = "datamaliciousorder - file 20151216_01f39d41b29644223efba73ecedd0e56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01495ee180b52b1bb00326917d3389f11bee8fe03d673a470d023ad7d0f206c6"

  strings:
    $s1  = "Math.cos(448), 2) - 1)));} DAWaEQhfk[xOMKYgGGFzn]++;}xOMKYgGGFzn++;} return GcjIduWThJA}" fullword ascii
    $s2  = ") - 1));while(true){if (xOMKYgGGFzn >= (4120+464)/764){break;}DAWaEQhfk[xOMKYgGGFzn]=Math.round((Math.pow(Math.sin(92), 2) + Mat" ascii
    $s3  = "function aTuEVxEAHEliKXoHa(UykLm){GcjIduWThJA= '';xOMKYgGGFzn=Math.round((Math.pow(Math.sin(614), 2) + Math.pow(Math.cos(614), 2" ascii
    $s4  = "h.pow(Math.cos(92), 2) - 1)); while(true) { if(DAWaEQhfk[xOMKYgGGFzn] > UykLm[xOMKYgGGFzn].length-(465+83)/548) { break; } if (G" ascii
    $s5  = "function aTuEVxEAHEliKXoHa(UykLm){GcjIduWThJA= '';xOMKYgGGFzn=Math.round((Math.pow(Math.sin(614), 2) + Math.pow(Math.cos(614), 2" ascii
    $s6  = "function GNptMsj(bYlsBkxgPgWcZmrHtOkNRAVzdQVqRdqpESzK) {return !KhmzQVIrJlc(qsbWUiSeVjKHkJu(bYlsBkxgPgWcZmrHtOkNRAVzdQVqRdqpESzK" ascii
    $s7  = "function a(RAvboCSZNCem,mMFuRlISpIVtQI){RAvboCSZNCem.push(mMFuRlISpIVtQI);}" fullword ascii
    $s8  = "function jcJTipxKPeRHyXs(hTatQoUUzQFLtNlmk,fbwWIWBhIrJXirnPXGwBsZFWlXhKbLYGhO,AMUxFZQbDhLJhvuSYGZOOTLhTEwjDSZWIHJ){eval(hTatQoUU" ascii
    $s9  = "U);return NWIbf;}" fullword ascii
    $s10 = "function jCunGEMsGmRWmoJXaBRMwbDUQazVPNvkCjejpFXZnolmPJdtQMgESC(pYyfVxGyKNHXi,eVCtbgBrrTMcPh){ return GlJBcxN[uIzSeRKl[nbkvN(pYy" ascii
    $s11 = "function jCunGEMsGmRWmoJXaBRMwbDUQazVPNvkCjejpFXZnolmPJdtQMgESC(pYyfVxGyKNHXi,eVCtbgBrrTMcPh){ return GlJBcxN[uIzSeRKl[nbkvN(pYy" ascii
    $s12 = "function FmqvTTsaPhKd(NXncDjdkNwKXq) {return isFinite(NXncDjdkNwKXq);}" fullword ascii
    $s13 = "function jcJTipxKPeRHyXs(hTatQoUUzQFLtNlmk,fbwWIWBhIrJXirnPXGwBsZFWlXhKbLYGhO,AMUxFZQbDhLJhvuSYGZOOTLhTEwjDSZWIHJ){eval(hTatQoUU" ascii
    $s14 = "function GNptMsj(bYlsBkxgPgWcZmrHtOkNRAVzdQVqRdqpESzK) {return !KhmzQVIrJlc(qsbWUiSeVjKHkJu(bYlsBkxgPgWcZmrHtOkNRAVzdQVqRdqpESzK" ascii
    $s15 = "function qsbWUiSeVjKHkJu(DSUcZVteoYHKEeXqhfO) {return parseFloat(DSUcZVteoYHKEeXqhfO);}" fullword ascii
    $s16 = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s17 = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s18 = "function nbkvN(CGpkqvLQrmV,plhiXrxwxqTov,ztYPxQCU){QlTm=eikGAPBmfPJMSUWKQ(CGpkqvLQrmV,plhiXrxwxqTov);NWIbf=QlTm.toString(ztYPxQC" ascii
    $s19 = "function X(zLFpXBRLAKEtFN,kBDNFUoRbTRJA,OEuQlKDPCxB) {zLFpXBRLAKEtFN[kBDNFUoRbTRJA]=OEuQlKDPCxB;}" fullword ascii
    $s20 = "function nbkvN(CGpkqvLQrmV,plhiXrxwxqTov,ztYPxQCU){QlTm=eikGAPBmfPJMSUWKQ(CGpkqvLQrmV,plhiXrxwxqTov);NWIbf=QlTm.toString(ztYPxQC" ascii

  condition:
    uint16(0) == 0x4975 and
    8 of them
}