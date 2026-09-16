rule sig_20151217_5c67166117cca44b7783366de86fb86f {
  meta:
    description = "datamaliciousorder - file 20151217_5c67166117cca44b7783366de86fb86f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56dd361869074b0919eafd26eb5e1460c8d6867ec5841db96cc282261edee90f"

  strings:
    $s1  = "function WliWjawTKrvMJWeQk(wBhXn){mErEIAvqgPE= '';oCSfbwtcRhs=Math.round((Math.pow(Math.sin(987), 2) + Math.pow(Math.cos(987), 2" ascii
    $s2  = "ow(Math.cos(482), 2) - 1)));} mFVNKVbZo[oCSfbwtcRhs]++;}oCSfbwtcRhs++;} return mErEIAvqgPE}" fullword ascii
    $s3  = ") - 1));while(true){if (oCSfbwtcRhs >= (1836+582)/403){break;}mFVNKVbZo[oCSfbwtcRhs]=Math.round((Math.pow(Math.sin(891), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(891), 2) - 1)); while(true) { if(mFVNKVbZo[oCSfbwtcRhs] > wBhXn[oCSfbwtcRhs].length-(739+227)/966) { break; } if" ascii
    $s5  = "function WliWjawTKrvMJWeQk(wBhXn){mErEIAvqgPE= '';oCSfbwtcRhs=Math.round((Math.pow(Math.sin(987), 2) + Math.pow(Math.cos(987), 2" ascii
    $s6  = "function HgacGFXwzDSJvxt(SYTZclytzbrcbzifR,OaFwtgdBnzydPthEqLIiTCTPLijiXRLEhi,NuJVJTOleyErjAbpHgHKcxQeasqzzhePNTg){eval(SYTZclyt" ascii
    $s7  = "function HgacGFXwzDSJvxt(SYTZclytzbrcbzifR,OaFwtgdBnzydPthEqLIiTCTPLijiXRLEhi,NuJVJTOleyErjAbpHgHKcxQeasqzzhePNTg){eval(SYTZclyt" ascii
    $s8  = "function ZRpDpqf(FWhhlPWqJtfGvwaTMuSdcsMxnlysdnpOUrKu) {return !PyQkUhueIbs(CTDMVTwGGCgHkfN(FWhhlPWqJtfGvwaTMuSdcsMxnlysdnpOUrKu" ascii
    $s9  = "function CTDMVTwGGCgHkfN(bpziTpzCHWpipezkcAk) {return parseFloat(bpziTpzCHWpipezkcAk);}" fullword ascii
    $s10 = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii
    $s11 = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii
    $s12 = "function k(gMsLTPDUwUXh,tMJLYKlSHbBryE){gMsLTPDUwUXh.push(tMJLYKlSHbBryE);}" fullword ascii
    $s13 = "function WjZYOuSWkShjNyzKU(fLGfNacbNP,mMCqwDatHp) {return parseInt(fLGfNacbNP,mMCqwDatHp);}" fullword ascii
    $s14 = "function YxwFxesmnrCc(SysxMqmXCYmJp) {return isFinite(SysxMqmXCYmJp);}" fullword ascii
    $s15 = "function PyQkUhueIbs(uSevOLyzJjOaZY) {return isNaN(uSevOLyzJjOaZY);}" fullword ascii
    $s16 = "e);return DqjaU;}" fullword ascii
    $s17 = "function j(KYwMBkJshkdtUz,XjSFBtHrwSQeP,wTGPSrxJXsa) {KYwMBkJshkdtUz[XjSFBtHrwSQeP]=wTGPSrxJXsa;}" fullword ascii
    $s18 = "function GWjui(XBMrIjRInrG,klLhCyNCzPqGs,JZUBjvUe){pETZ=WjZYOuSWkShjNyzKU(XBMrIjRInrG,klLhCyNCzPqGs);DqjaU=pETZ.toString(JZUBjvU" ascii
    $s19 = "function GWjui(XBMrIjRInrG,klLhCyNCzPqGs,JZUBjvUe){pETZ=WjZYOuSWkShjNyzKU(XBMrIjRInrG,klLhCyNCzPqGs);DqjaU=pETZ.toString(JZUBjvU" ascii
    $s20 = "function ZRpDpqf(FWhhlPWqJtfGvwaTMuSdcsMxnlysdnpOUrKu) {return !PyQkUhueIbs(CTDMVTwGGCgHkfN(FWhhlPWqJtfGvwaTMuSdcsMxnlysdnpOUrKu" ascii

  condition:
    uint16(0) == 0x5575 and
    8 of them
}