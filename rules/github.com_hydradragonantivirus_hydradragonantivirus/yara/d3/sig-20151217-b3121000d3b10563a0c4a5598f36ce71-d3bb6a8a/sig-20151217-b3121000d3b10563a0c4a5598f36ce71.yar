rule sig_20151217_b3121000d3b10563a0c4a5598f36ce71 {
  meta:
    description = "datamaliciousorder - file 20151217_b3121000d3b10563a0c4a5598f36ce71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12104609a91140fb40f49eef2da6629912ee3941fa84450446dd81a3250a63ea"

  strings:
    $s1  = "ath.cos(61), 2) - 1)));} swbCSBFkN[tSZWHySvhRk]++;}tSZWHySvhRk++;} return WJhitqLmbkZ}" fullword ascii
    $s2  = "h.pow(Math.cos(739), 2) - 1)); while(true) { if(swbCSBFkN[tSZWHySvhRk] > hAyPt[tSZWHySvhRk].length-(-326+768)/442) { break; } if" ascii
    $s3  = ") - 1));while(true){if (tSZWHySvhRk >= (346+854)/200){break;}swbCSBFkN[tSZWHySvhRk]=Math.round((Math.pow(Math.sin(739), 2) + Mat" ascii
    $s4  = "function lQWaGTqvbatRLEFDK(hAyPt){WJhitqLmbkZ= '';tSZWHySvhRk=Math.round((Math.pow(Math.sin(791), 2) + Math.pow(Math.cos(791), 2" ascii
    $s5  = "function FVdQaOa(btjYdBgpHVZWeZJLmbvyqErmOcFAEuOLlmbC) {return !kXuuiRFSMtp(XcEoMbllsdhPLwB(btjYdBgpHVZWeZJLmbvyqErmOcFAEuOLlmbC" ascii
    $s6  = "function lQWaGTqvbatRLEFDK(hAyPt){WJhitqLmbkZ= '';tSZWHySvhRk=Math.round((Math.pow(Math.sin(791), 2) + Math.pow(Math.cos(791), 2" ascii
    $s7  = "function kXuuiRFSMtp(CNxwukoTEBYFbY) {return isNaN(CNxwukoTEBYFbY);}" fullword ascii
    $s8  = "function FVdQaOa(btjYdBgpHVZWeZJLmbvyqErmOcFAEuOLlmbC) {return !kXuuiRFSMtp(XcEoMbllsdhPLwB(btjYdBgpHVZWeZJLmbvyqErmOcFAEuOLlmbC" ascii
    $s9  = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s10 = "function p(wtXxxoPxaPLa,UnoUwKvZcOvAAf){wtXxxoPxaPLa.push(UnoUwKvZcOvAAf);}" fullword ascii
    $s11 = "function y(tkWumFgiFWYeyk,IPgrirbkgfqla,GiuvqokGNSx) {tkWumFgiFWYeyk[IPgrirbkgfqla]=GiuvqokGNSx;}" fullword ascii
    $s12 = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s13 = "function cqbpN(oQqONmoNEly,ZiXHPBpjpeYjU,EkLvBmiP){sLNv=iWMbePEzsEFSEmCuv(oQqONmoNEly,ZiXHPBpjpeYjU);QNABB=sLNv.toString(EkLvBmi" ascii
    $s14 = "function cqbpN(oQqONmoNEly,ZiXHPBpjpeYjU,EkLvBmiP){sLNv=iWMbePEzsEFSEmCuv(oQqONmoNEly,ZiXHPBpjpeYjU);QNABB=sLNv.toString(EkLvBmi" ascii
    $s15 = "function npITIavXCnSDwkzhmqhLwRzjbykbOVCPnWqykxtvFZFVHKRfCdrRRl(TQTfEHyhiMaVa,lHjjEdNYUPqxRM){ return JvlOjXQ[gwPqGykw[cqbpN(TQT" ascii
    $s16 = "function GhkNBRIFKWwXBJr(LLOmYGDMhhSJfKUDK,JFAMEqKBpSwaGtwGuqtrCccTuyySxVKqeU,SslqEsOsrallfIrJMxOGkPtMmhiiKrvseLv){eval(LLOmYGDM" ascii
    $s17 = "function GhkNBRIFKWwXBJr(LLOmYGDMhhSJfKUDK,JFAMEqKBpSwaGtwGuqtrCccTuyySxVKqeU,SslqEsOsrallfIrJMxOGkPtMmhiiKrvseLv){eval(LLOmYGDM" ascii
    $s18 = "P);return QNABB;}" fullword ascii
    $s19 = "function XcEoMbllsdhPLwB(xFUzOjtqITUoOHxEnyb) {return parseFloat(xFUzOjtqITUoOHxEnyb);}" fullword ascii
    $s20 = "function IKVkROBCKbJo(AzHVPsBPrNwnJ) {return isFinite(AzHVPsBPrNwnJ);}" fullword ascii

  condition:
    uint16(0) == 0x7767 and
    8 of them
}