rule sig_20160531_7c24499b13de29c56e5883562270916b {
  meta:
    description = "datamaliciousorder - file 20160531_7c24499b13de29c56e5883562270916b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46ef2287e3f7ede4d6ddb912c202427b6f9f609a459919b531fc6d7161971a87"

  strings:
    $s1  = "var dJGITPTE=function(){return WScript.CreateObject(IwnEbiHdMnfinEPYlJprE[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function yXolEugglmyKcv(jmjxD,vkrymm){return jmjxD.charAt(vkrymm);}" fullword ascii
    $s3  = "f;jnHzidbOTSrnAirZCCvLpNf = kkylFS & 0xff;if (bDeAEnGZhicFSEp == 64) VtXiGw += YF(AfQjrAVd);else if (gLAvjkYP == 64) VtXiGw += P" ascii
    $s4  = "push(\"U\");gdnEGYAwiLzN.push(\"V\");gdnEGYAwiLzN.push(\"W\");gdnEGYAwiLzN.push(\"X\");gdnEGYAwiLzN.push(\"Y\");gdnEGYAwiLzN.pus" ascii
    $s5  = "function JsFSnesTfVjKY(){return dJGITPTE.ExpandEnvironmentStrings(ILHdH())}" fullword ascii
    $s6  = "Jig < LBybmGDbsXjew.length);return VtXiGw;}" fullword ascii
    $s7  = "function gZNOkWm(pzjFVSDvyGYDNVF,ttqpCjkJTjmBPQVOnyVcOl){return pzjFVSDvyGYDNVF.indexOf(ttqpCjkJTjmBPQVOnyVcOl);}" fullword ascii
    $s8  = "function FiDnNY(LBybmGDbsXjew) {var YtPifktBwPSCBTICtaJt = gdnEGYAwiLzN.join(IwnEbiHdMnfinEPYlJprE[7]);var AfQjrAVd, GUkvIUMcohu" ascii
    $s9  = "function WXGQxN(GUaNKcpVT,udiKTY,OpupHVBrPe){ljrsHUVsgX=GUaNKcpVT.split(OpupHVBrPe);GsxwwOWHQV = IwnEbiHdMnfinEPYlJprE[0];for(Py" ascii
    $s10 = "function WXGQxN(GUaNKcpVT,udiKTY,OpupHVBrPe){ljrsHUVsgX=GUaNKcpVT.split(OpupHVBrPe);GsxwwOWHQV = IwnEbiHdMnfinEPYlJprE[0];for(Py" ascii
    $s11 = "function GfGNpiqGLUfoss(QvKxvisgl,gqWEtlBLjaJJwr,PPtgarBw){return String.fromCharCode(QvKxvisgl,gqWEtlBLjaJJwr,PPtgarBw);}" fullword ascii
    $s12 = "JZGo=0;PyJZGo<udiKTY.length;PyJZGo++) {GsxwwOWHQV+=ljrsHUVsgX[udiKTY[PyJZGo]];}return GsxwwOWHQV.substring(3,GsxwwOWHQV.length);" ascii
    $s13 = "(ONiioqxcIB,0x1,0x0)}function zeTKVnvuOke(ZpWfn,GtNKJjHbw,OoMyyLhTEXb){var ddQoX=ZpWfn.createtextfile(GtNKJjHbw,true);ddQoX.Writ" ascii
    $s14 = "function bLQphKa(){return WXGQxN(IwnEbiHdMnfinEPYlJprE[11],[2,4,8,10],IwnEbiHdMnfinEPYlJprE[12]);}" fullword ascii
    $s15 = "function PZdFaQivrm(rZPoqQgmQWfmVimck,JzkMqIeVyVkCvJOVbMmdLRu){return String.fromCharCode(rZPoqQgmQWfmVimck,JzkMqIeVyVkCvJOVbMmd" ascii
    $s16 = "function PZdFaQivrm(rZPoqQgmQWfmVimck,JzkMqIeVyVkCvJOVbMmdLRu){return String.fromCharCode(rZPoqQgmQWfmVimck,JzkMqIeVyVkCvJOVbMmd" ascii
    $s17 = "ZdFaQivrm(AfQjrAVd, GUkvIUMcohui);else VtXiGw += GfGNpiqGLUfoss(AfQjrAVd, GUkvIUMcohui, jnHzidbOTSrnAirZCCvLpNf);} while (ICZHtQ" ascii
    $s18 = "function koyARDElsxfJg(){return WXGQxN(IwnEbiHdMnfinEPYlJprE[13],[0,3,6],IwnEbiHdMnfinEPYlJprE[14]);}" fullword ascii
    $s19 = "var GagYAhToroWQ=function(){return new ActiveXObject(IwnEbiHdMnfinEPYlJprE[1]);}();" fullword ascii
    $s20 = "(ONiioqxcIB,0x1,0x0)}function zeTKVnvuOke(ZpWfn,GtNKJjHbw,OoMyyLhTEXb){var ddQoX=ZpWfn.createtextfile(GtNKJjHbw,true);ddQoX.Writ" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}