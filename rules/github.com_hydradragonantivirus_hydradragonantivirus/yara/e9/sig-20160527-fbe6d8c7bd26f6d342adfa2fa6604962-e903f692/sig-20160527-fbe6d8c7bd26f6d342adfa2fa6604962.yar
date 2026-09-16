rule sig_20160527_fbe6d8c7bd26f6d342adfa2fa6604962 {
  meta:
    description = "datamaliciousorder - file 20160527_fbe6d8c7bd26f6d342adfa2fa6604962.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3676c90bcd9f232fdae47cfdd99492eea8ade1b884e67a12b019fb4a16f438d"

  strings:
    $s1  = "function BcWCJW() {return WScript;}function GHxyBswwaod(){return wSsuIJUtMZTqSn.ExpandEnvironmentStrings(TbBowhlyBL())}" fullword ascii
    $s2  = "function WczVRikzmqtwKkB(qqRZmR,oScNgCXBsYLX){return qqRZmR.charAt(oScNgCXBsYLX);}" fullword ascii
    $s3  = "function CDXVrMtaD(lfvZUvbAGeAz,obmfoQJE,VZmulPhUKOAqoY){YigDTvrZr=lfvZUvbAGeAz.split(VZmulPhUKOAqoY);VFrterVOjnNtYp = xdWExjReq" ascii
    $s4  = "function dfHmslaz(xHQWWvqLlXCbywlPpUeqOXF,joHMDGi,IcTiCylVqShAiAGUJ){return String.fromCharCode(xHQWWvqLlXCbywlPpUeqOXF,joHMDGi," ascii
    $s5  = "function MMmxW(mQhhsrcSyaVisDMtOcgmyyN,NhTnNquTaiKCKCLUOyPxptpC){return String.fromCharCode(mQhhsrcSyaVisDMtOcgmyyN,NhTnNquTaiKC" ascii
    $s6  = "function OwcPukctink(AgnyWhEKLpgBq) {var coyVSVkSjqFnb = tKMKMeLrfQTpzMZ.join(xdWExjReqHoahqfpFhq[6]);var BgEdBXIIUQVcqtKAE, NUJ" ascii
    $s7  = "function CDXVrMtaD(lfvZUvbAGeAz,obmfoQJE,VZmulPhUKOAqoY){YigDTvrZr=lfvZUvbAGeAz.split(VZmulPhUKOAqoY);VFrterVOjnNtYp = xdWExjReq" ascii
    $s8  = "function BaolwWXfwTaC(TgqLEYK,OfHlhNHmcR) {var KCRqswn=[xdWExjReqHoahqfpFhq[15]];TgqLEYK[KCRqswn[0]](OfHlhNHmcR,0x1,0x0)}" fullword ascii
    $s9  = "function TbBowhlyBL(){return CDXVrMtaD(xdWExjReqHoahqfpFhq[8],[1,5,7],xdWExjReqHoahqfpFhq[9]);}" fullword ascii
    $s10 = "function JOlhGVhgXrXduAxQW(tpduPVQkavFPMoLpxu,gosHDcU){return tpduPVQkavFPMoLpxu.indexOf(gosHDcU);}" fullword ascii
    $s11 = "IqThz = fFagGjBh & 0xff;if (hLsfwkseDBZwT == 64) qpWdwwxCCJfWvAeCqyIzUfgq += DcD(BgEdBXIIUQVcqtKAE);else if (cgWLvUvoKBSLJ == 64" ascii
    $s12 = "var WPGfBMKGSD = XnxcuouUxkqF.createtextfile(wSsuIJUtMZTqSn.ExpandEnvironmentStrings(xdWExjReqHoahqfpFhq[2]+xdWExjReqHoahqfpFhq[" ascii
    $s13 = "var XnxcuouUxkqF=function(){return new ActiveXObject(xdWExjReqHoahqfpFhq[0]);}();" fullword ascii
    $s14 = ") qpWdwwxCCJfWvAeCqyIzUfgq += MMmxW(BgEdBXIIUQVcqtKAE, NUJZbfVbpenCSnPIYawcxmg);else qpWdwwxCCJfWvAeCqyIzUfgq += dfHmslaz(BgEdBX" ascii
    $s15 = "3])+String.fromCharCode(92)+xdWExjReqHoahqfpFhq[4],true);" fullword ascii
    $s16 = "function KSVyVvJ(){return CDXVrMtaD(xdWExjReqHoahqfpFhq[10],[2,4,8,10],xdWExjReqHoahqfpFhq[11]);}" fullword ascii
    $s17 = "function dfHmslaz(xHQWWvqLlXCbywlPpUeqOXF,joHMDGi,IcTiCylVqShAiAGUJ){return String.fromCharCode(xHQWWvqLlXCbywlPpUeqOXF,joHMDGi," ascii
    $s18 = "IIUQVcqtKAE, NUJZbfVbpenCSnPIYawcxmg, KcgPruGyIGPVkIqThz);} while (AHmKTqtYe < AgnyWhEKLpgBq.length);return qpWdwwxCCJfWvAeCqyIz" ascii
    $s19 = "function zsxoEcQWq(){return CDXVrMtaD(xdWExjReqHoahqfpFhq[12],[0,3,6],xdWExjReqHoahqfpFhq[13]);}" fullword ascii
    $s20 = "function OwcPukctink(AgnyWhEKLpgBq) {var coyVSVkSjqFnb = tKMKMeLrfQTpzMZ.join(xdWExjReqHoahqfpFhq[6]);var BgEdBXIIUQVcqtKAE, NUJ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}