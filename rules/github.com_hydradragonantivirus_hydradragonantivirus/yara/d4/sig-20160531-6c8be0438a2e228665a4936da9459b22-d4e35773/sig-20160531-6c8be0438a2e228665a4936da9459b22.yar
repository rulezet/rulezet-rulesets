rule sig_20160531_6c8be0438a2e228665a4936da9459b22 {
  meta:
    description = "datamaliciousorder - file 20160531_6c8be0438a2e228665a4936da9459b22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c338a48d1a2080f3ab3a28315e19be87538bd7e74701590f591c5622b6e234c"

  strings:
    $s1  = "var BKUUBc=function(){return WScript.CreateObject(xujvMJWURzlXaGdk[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function mVteL(ohTKSfi,mzakrtWnrwAERmTsoSpCgf){return ohTKSfi.charAt(mzakrtWnrwAERmTsoSpCgf);}" fullword ascii
    $s3  = ";for(FBZLacoZM=0;FBZLacoZM<hsfFNXqU.length;FBZLacoZM++) {YEclI+=KwWnFMw[hsfFNXqU[FBZLacoZM]];}return YEclI.substring(3,YEclI.len" ascii
    $s4  = "(sktxoJhkPhv,0x1,0x0)}function ilVxNneuff(jyKmaLxBh,tTeSVRSiQmOM,kgrKNPJPUYnalZ){var cPUfbiWPqZCoXv=jyKmaLxBh.createtextfile(tTe" ascii
    $s5  = "YGxDOBRpSQcGqtAv == 64) jKPYFs += DRSjlfEYwZQCyfq(QqQZkm, mKZkWCBcIbnAbNoIwEYI);else jKPYFs += tpKKLMvhWhgYGiIXmUUfS(QqQZkm, mKZ" ascii
    $s6  = "function CWmdugLIZBZPBZ(KznPmhoHLRyFM,hsfFNXqU,liHkGjufblW){KwWnFMw=KznPmhoHLRyFM.split(liHkGjufblW);YEclI = xujvMJWURzlXaGdk[0]" ascii
    $s7  = "function DRSjlfEYwZQCyfq(iBuASaEYbEbuLVM,VZNfmbOQGOCtHsvATmKcJqk){return String.fromCharCode(iBuASaEYbEbuLVM,VZNfmbOQGOCtHsvATmK" ascii
    $s8  = "function fu(scNJBwnWRZuwoNzRZYgtM){return String.fromCharCode(scNJBwnWRZuwoNzRZYgtM);}" fullword ascii
    $s9  = "var lDJnSAAaCPgAK=function(){return new ActiveXObject(xujvMJWURzlXaGdk[1]);}();" fullword ascii
    $s10 = "kWCBcIbnAbNoIwEYI, ysGZepCtuuAxybD);} while (NEoJHEbysvdhZz < PSHkYBdhFRlXG.length);return jKPYFs;}" fullword ascii
    $s11 = "oVxZjGbfjhQn>> 8 & 0xff;ysGZepCtuuAxybD = VmEpczoVxZjGbfjhQn & 0xff;if (BUEriBYMsNRep == 64) jKPYFs += fu(QqQZkm);else if (shKNh" ascii
    $s12 = "SVRSiQmOM,true);cPUfbiWPqZCoXv.WriteLine(kgrKNPJPUYnalZ);cPUfbiWPqZCoXv.Close();}" fullword ascii
    $s13 = "function KpWRBMDon(PSHkYBdhFRlXG) {var SWYKunCy = rkBdT.join(xujvMJWURzlXaGdk[7]);var QqQZkm, mKZkWCBcIbnAbNoIwEYI, ysGZepCtuuAx" ascii
    $s14 = "function tpKKLMvhWhgYGiIXmUUfS(jgzQKOJylS,JzkIlb,TUsUnEAHxKYQNJuxO){return String.fromCharCode(jgzQKOJylS,JzkIlb,TUsUnEAHxKYQNJu" ascii
    $s15 = "function WIEEt(vpkCEIVnvnBpuRqedKSni,yUKAVbYgofg){return vpkCEIVnvnBpuRqedKSni.indexOf(yUKAVbYgofg);}" fullword ascii
    $s16 = "(sktxoJhkPhv,0x1,0x0)}function ilVxNneuff(jyKmaLxBh,tTeSVRSiQmOM,kgrKNPJPUYnalZ){var cPUfbiWPqZCoXv=jyKmaLxBh.createtextfile(tTe" ascii
    $s17 = "function lqEGGC(){return CWmdugLIZBZPBZ(xujvMJWURzlXaGdk[9],[1,5,7],xujvMJWURzlXaGdk[10]);}" fullword ascii
    $s18 = "function ZpcJblGPHl(){return CWmdugLIZBZPBZ(xujvMJWURzlXaGdk[11],[2,4,8,10],xujvMJWURzlXaGdk[12]);}" fullword ascii
    $s19 = "function eIveex(){return CWmdugLIZBZPBZ(xujvMJWURzlXaGdk[13],[0,3,6],xujvMJWURzlXaGdk[14]);}" fullword ascii
    $s20 = "function DRSjlfEYwZQCyfq(iBuASaEYbEbuLVM,VZNfmbOQGOCtHsvATmKcJqk){return String.fromCharCode(iBuASaEYbEbuLVM,VZNfmbOQGOCtHsvATmK" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}