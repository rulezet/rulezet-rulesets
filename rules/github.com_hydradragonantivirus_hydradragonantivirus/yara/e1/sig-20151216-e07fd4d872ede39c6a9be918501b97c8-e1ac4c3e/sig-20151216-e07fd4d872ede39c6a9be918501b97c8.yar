rule sig_20151216_e07fd4d872ede39c6a9be918501b97c8 {
  meta:
    description = "datamaliciousorder - file 20151216_e07fd4d872ede39c6a9be918501b97c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fd949d54e3588974f59442d579cbef3ba07a1537f97a1e95e44f428ebf92299"

  strings:
    $s1  = ") - 1));while(true){if (HyQxLRgfsPq >= (3151+65)/536){break;}eFbGPMVSo[HyQxLRgfsPq]=Math.round((Math.pow(Math.sin(207), 2) + Mat" ascii
    $s2  = "pow(Math.cos(327), 2) - 1)));} eFbGPMVSo[HyQxLRgfsPq]++;}HyQxLRgfsPq++;} return bSUFkAoFPWH}" fullword ascii
    $s3  = "function HkCIYFaehJSAFHkVl(qeycX){bSUFkAoFPWH= '';HyQxLRgfsPq=Math.round((Math.pow(Math.sin(295), 2) + Math.pow(Math.cos(295), 2" ascii
    $s4  = "h.pow(Math.cos(207), 2) - 1)); while(true) { if(eFbGPMVSo[HyQxLRgfsPq] > qeycX[HyQxLRgfsPq].length-(-395+594)/199) { break; } if" ascii
    $s5  = "function GQbMidK(pHExPMuBsxlygetERbsItxeeDhQoStyARuoB) {return !lkbuOAdZgai(rrzVQoqraFEEHvL(pHExPMuBsxlygetERbsItxeeDhQoStyARuoB" ascii
    $s6  = "function HkCIYFaehJSAFHkVl(qeycX){bSUFkAoFPWH= '';HyQxLRgfsPq=Math.round((Math.pow(Math.sin(295), 2) + Math.pow(Math.cos(295), 2" ascii
    $s7  = "ILkNwABpgMUZsIxNWqLSnNqWCtdBhFGXdie([qeycX[HyQxLRgfsPq][eFbGPMVSo[HyQxLRgfsPq]]], Math.round((Math.pow(Math.sin(327), 2) + Math." ascii
    $s8  = "function GQbMidK(pHExPMuBsxlygetERbsItxeeDhQoStyARuoB) {return !lkbuOAdZgai(rrzVQoqraFEEHvL(pHExPMuBsxlygetERbsItxeeDhQoStyARuoB" ascii
    $s9  = "function lkbuOAdZgai(lUAoCOMSYhLRhn) {return isNaN(lUAoCOMSYhLRhn);}" fullword ascii
    $s10 = "var k = new Array();k[0]=[];k[0][0]='d';k[0][1]='a';k[0][2]='d';k[0][3]='a';k[0][4]='46';k[0][5]='3d';k[0][6]='42';k[0][7]='14';" ascii
    $s11 = "function C(TVjVKnNemkrJ,RgOviFWUfwkfjL){TVjVKnNemkrJ.push(RgOviFWUfwkfjL);}" fullword ascii
    $s12 = "L);return UPxIy;}" fullword ascii
    $s13 = "function jyLyy(iNARNsEQqgm,ErpBYRVybkuSh,FkfOpfQL){RHEf=FpGtjgxSJmsHXFbjq(iNARNsEQqgm,ErpBYRVybkuSh);UPxIy=RHEf.toString(FkfOpfQ" ascii
    $s14 = "function WlfYkPJDbuXd(LHzYAUnlEOcFI) {return isFinite(LHzYAUnlEOcFI);}" fullword ascii
    $s15 = "function pofisgXAaUAKAvhffioILkNwABpgMUZsIxNWqLSnNqWCtdBhFGXdie(EwWMNHpadQJMV,ypNLDqlWRbQxnv){ return DWZozWW[AIgqsYet[jyLyy(EwW" ascii
    $s16 = "function zobZTuIcMtFsiBV(ekPYkNVKZavEetFNt,BbgIMfEmVwGOhsTnJQqkSYTdwDBRYisqub,nXSpcrezcQVlCHzUTmYiuWMngIRAAsjgemz){eval(ekPYkNVK" ascii
    $s17 = "function pofisgXAaUAKAvhffioILkNwABpgMUZsIxNWqLSnNqWCtdBhFGXdie(EwWMNHpadQJMV,ypNLDqlWRbQxnv){ return DWZozWW[AIgqsYet[jyLyy(EwW" ascii
    $s18 = "function FpGtjgxSJmsHXFbjq(pbmmnDNmhV,QbpzNbYfdI) {return parseInt(pbmmnDNmhV,QbpzNbYfdI);}" fullword ascii
    $s19 = "function rrzVQoqraFEEHvL(BtXzhrvlssWEjZrXtdl) {return parseFloat(BtXzhrvlssWEjZrXtdl);}" fullword ascii
    $s20 = "function zobZTuIcMtFsiBV(ekPYkNVKZavEetFNt,BbgIMfEmVwGOhsTnJQqkSYTdwDBRYisqub,nXSpcrezcQVlCHzUTmYiuWMngIRAAsjgemz){eval(ekPYkNVK" ascii

  condition:
    uint16(0) == 0x4941 and
    8 of them
}