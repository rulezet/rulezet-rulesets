rule sig_20160531_07b3603958749c7f5cd896867f074222 {
  meta:
    description = "datamaliciousorder - file 20160531_07b3603958749c7f5cd896867f074222.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd43a232b177dfa6e8ccdde8e82718e4921f6efa439afa9ba90b811bdb331cb9"

  strings:
    $s1  = "var vKTGrIqdg=function(){return WScript.CreateObject(DgkeU[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ziBAszmRWWqXU(PwXRsFYxpTebw,yDoObEGyzqcMnKFfOvbSo){return PwXRsFYxpTebw.charAt(yDoObEGyzqcMnKFfOvbSo);}" fullword ascii
    $s3  = "ZAWu.length);return tUIXydnjT;}" fullword ascii
    $s4  = "function rbWMILUZ(JgObVWZHSzs,ToSAIykMY) {var IbAdGPjpypRHI=[DgkeU[15]];JgObVWZHSzs[IbAdGPjpypRHI[0]]" fullword ascii
    $s5  = "function WzpzWxsYbqqwi(eQgTgDjFAZAWu) {var yVIPsQcTVBbxcQHsGID = lkorUYdEYc.join(DgkeU[7]);var ghNBVlnknVdelh, wgVvZN, gciuHAjWw" ascii
    $s6  = "function lJOXGJDVOILck(){return KnZZcRVsUp(DgkeU[13],[0,3,6],DgkeU[14]);}" fullword ascii
    $s7  = "YqoOCpvndvAKXGJt == 64) tUIXydnjT += K(ghNBVlnknVdelh);else if (HthYk == 64) tUIXydnjT += skIQgdlrEaHySqECTXGcSYqD(ghNBVlnknVdel" ascii
    $s8  = "function KnZZcRVsUp(RoUSw,CLIrrJ,ZTqBjpnF){cwGLjBmaV=RoUSw.split(ZTqBjpnF);HVCOwsklzGMMNs = DgkeU[0];for(mqCbefRJeeiDow=0;mqCbef" ascii
    $s9  = "function PuCosKGJaihELFxlBhKUOCYG(ElVOvEeSbo,koVQVokjdEK,qFItsZZpQSYcGczbFz){return String.fromCharCode(ElVOvEeSbo,koVQVokjdEK,q" ascii
    $s10 = "function WzpzWxsYbqqwi(eQgTgDjFAZAWu) {var yVIPsQcTVBbxcQHsGID = lkorUYdEYc.join(DgkeU[7]);var ghNBVlnknVdelh, wgVvZN, gciuHAjWw" ascii
    $s11 = "(ToSAIykMY,0x1,0x0)}function hXrjdpPZMhc(ZQrGU,RpWeptYbPW,anmXK){var PnxFJZpDZH=ZQrGU.createtextfile(RpWeptYbPW,true);PnxFJZpDZH" ascii
    $s12 = "function qTEHWuurRUYV(){return vKTGrIqdg.ExpandEnvironmentStrings(dHwOHtsBbCIRx())}" fullword ascii
    $s13 = "var Sdxaj=function(){return new ActiveXObject(DgkeU[1]);}();" fullword ascii
    $s14 = "function dHwOHtsBbCIRx(){return KnZZcRVsUp(DgkeU[9],[1,5,7],DgkeU[10]);}" fullword ascii
    $s15 = "(ToSAIykMY,0x1,0x0)}function hXrjdpPZMhc(ZQrGU,RpWeptYbPW,anmXK){var PnxFJZpDZH=ZQrGU.createtextfile(RpWeptYbPW,true);PnxFJZpDZH" ascii
    $s16 = "function K(npNkbejUfdqxLYochQriSaV){return String.fromCharCode(npNkbejUfdqxLYochQriSaV);}" fullword ascii
    $s17 = "h, wgVvZN);else tUIXydnjT += PuCosKGJaihELFxlBhKUOCYG(ghNBVlnknVdelh, wgVvZN, gciuHAjWwqKFLZeLMFaxYD);} while (lnJtW < eQgTgDjFA" ascii
    $s18 = "RJeeiDow<CLIrrJ.length;mqCbefRJeeiDow++) {HVCOwsklzGMMNs+=cwGLjBmaV[CLIrrJ[mqCbefRJeeiDow]];}return HVCOwsklzGMMNs.substring(3,H" ascii
    $s19 = "push(\"K\");lkorUYdEYc.push(\"L\");lkorUYdEYc.push(\"a\");lkorUYdEYc.push(\"b\");lkorUYdEYc.push(\"c\");lkorUYdEYc.push(\"P\");l" ascii
    $s20 = "function VEAZpO(sHVTwIUywrNOL,RMauHXGxqDyJUddIHFlGBOW){return sHVTwIUywrNOL.indexOf(RMauHXGxqDyJUddIHFlGBOW);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}