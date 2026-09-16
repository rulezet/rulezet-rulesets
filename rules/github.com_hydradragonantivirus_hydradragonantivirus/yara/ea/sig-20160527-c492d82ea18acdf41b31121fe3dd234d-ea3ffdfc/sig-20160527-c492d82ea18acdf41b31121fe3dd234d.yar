rule sig_20160527_c492d82ea18acdf41b31121fe3dd234d {
  meta:
    description = "datamaliciousorder - file 20160527_c492d82ea18acdf41b31121fe3dd234d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7384774671091c572f9da53c51733de1b6553620480d7b93002a6e5262d7237"

  strings:
    $s1  = "function KfUhcENUg() {return WScript;}function nbMjATj(){return xsyhrqDRdHtW.ExpandEnvironmentStrings(EmaUhZ())}" fullword ascii
    $s2  = "function gcQozlgLjlQUY(sKuUOfNTST,GwVVeTaasYdSDDHHxzKkKQ){return sKuUOfNTST.charAt(GwVVeTaasYdSDDHHxzKkKQ);}" fullword ascii
    $s3  = "push(\"t\");ahLHMLHTAIYJiA.push(\"u\");ahLHMLHTAIYJiA.push(\"v\");ahLHMLHTAIYJiA.push(\"w\");ahLHMLHTAIYJiA.push(\"x\");ahLHMLHT" ascii
    $s4  = "LjQGNb & 0xff;if (gCBUaruNMQlJRAUcTn == 64) zNRiXeEEBkDsmMhPhhJOTWM += hI(dhXZGDustjW);else if (JWuMzPLzSAyvNPaRXXbyTJ == 64) zN" ascii
    $s5  = "function KtsadOF(jMELhJzKqqbYu) {var EyXQtK = ahLHMLHTAIYJiA.join(uIEvNcpy[6]);var dhXZGDustjW, rzuJcx, qJHSH, MAJNEBM, THEzbUAu" ascii
    $s6  = "2)+uIEvNcpy[4],true);" fullword ascii
    $s7  = "JHSH);} while (rsoNVKwWFxZIcpMlT < jMELhJzKqqbYu.length);return zNRiXeEEBkDsmMhPhhJOTWM;}" fullword ascii
    $s8  = "function WeRZBmlXLwKMYkmxsKIIyOKs(klUKhtqZkspQEfFwwqqaHSMY,ONSvhGQZmnCmoWOQmtPdcRq){return klUKhtqZkspQEfFwwqqaHSMY.indexOf(ONSv" ascii
    $s9  = "function zdpkoThzKVzX(JIUsAaLGUnXas,APHitajhCx) {var cqFiLqz=[uIEvNcpy[15]];JIUsAaLGUnXas[cqFiLqz[0]](APHitajhCx,0x1,0x0)}" fullword ascii
    $s10 = "var GFKoNWuXcrC=function(){return new ActiveXObject(uIEvNcpy[0]);}();" fullword ascii
    $s11 = "function MDBuMNMTtpv(XJDpvll,aNbWMDQuJPx,bLWdbEJYlCB){gpjNaxEMTzClrP=XJDpvll.split(bLWdbEJYlCB);RQVEycmSXCGN = uIEvNcpy[14];for(" ascii
    $s12 = "var WnnRXEXvOz = GFKoNWuXcrC.createtextfile(xsyhrqDRdHtW.ExpandEnvironmentStrings(uIEvNcpy[2]+uIEvNcpy[3])+String.fromCharCode(9" ascii
    $s13 = "function KtsadOF(jMELhJzKqqbYu) {var EyXQtK = ahLHMLHTAIYJiA.join(uIEvNcpy[6]);var dhXZGDustjW, rzuJcx, qJHSH, MAJNEBM, THEzbUAu" ascii
    $s14 = "function ynmTr(){return MDBuMNMTtpv(uIEvNcpy[10],[2,4,8,10],uIEvNcpy[11]);}" fullword ascii
    $s15 = "function hWtrzpfeMPwsOqJ(AYHIZDhzcO,qukgUHzBWe){return String.fromCharCode(AYHIZDhzcO,qukgUHzBWe);}" fullword ascii
    $s16 = "function TVkCwVTS(){return MDBuMNMTtpv(uIEvNcpy[12],[0,3,6],uIEvNcpy[13]);}" fullword ascii
    $s17 = "function MDBuMNMTtpv(XJDpvll,aNbWMDQuJPx,bLWdbEJYlCB){gpjNaxEMTzClrP=XJDpvll.split(bLWdbEJYlCB);RQVEycmSXCGN = uIEvNcpy[14];for(" ascii
    $s18 = "function LfgtrBWsEGt(GlQdMsKljuTCy,LggenqITvTzIIgZfSVDqwHI,zhtymPcnYmWy){return String.fromCharCode(GlQdMsKljuTCy,LggenqITvTzIIg" ascii
    $s19 = "function LfgtrBWsEGt(GlQdMsKljuTCy,LggenqITvTzIIgZfSVDqwHI,zhtymPcnYmWy){return String.fromCharCode(GlQdMsKljuTCy,LggenqITvTzIIg" ascii
    $s20 = "var xsyhrqDRdHtW=function(){return KfUhcENUg().CreateObject(uIEvNcpy[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}