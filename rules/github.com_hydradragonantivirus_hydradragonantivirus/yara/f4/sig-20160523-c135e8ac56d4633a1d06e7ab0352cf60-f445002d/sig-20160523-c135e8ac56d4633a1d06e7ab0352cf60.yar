rule sig_20160523_c135e8ac56d4633a1d06e7ab0352cf60 {
  meta:
    description = "datamaliciousorder - file 20160523_c135e8ac56d4633a1d06e7ab0352cf60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92e192db89945d955abb2f3c5e5a117608f9a73a5ca4a2b85a5c92d8eca7871a"

  strings:
    $s1  = "function bmpxuLQxKj(MwKYRjbf,TpSnFdrUHXqT) {MwKYRjbf.Run(TpSnFdrUHXqT, 0x1, 0x0);}" fullword ascii
    $s2  = "function tmsTAmJnTi() {return/*chWHYtCIsQAUuZypisITaiXIroZAMVEYaLmUhWfKLpXySvQreaGwzeCmhnBduouMmeqvOnXlFwYXJwnvHDHyvapPEITXMzked" ascii
    $s3  = "function ywimbPvK(bUPcr) {var iRrNDKcm=cjRronNSAYXXqb[13];for(var WGNHY=0;WGNHY<bUPcr;WGNHY++){boUHr+=iRrNDKcm.charAt(Math.floor" ascii
    $s4  = "function ywimbPvK(bUPcr) {var iRrNDKcm=cjRronNSAYXXqb[13];for(var WGNHY=0;WGNHY<bUPcr;WGNHY++){boUHr+=iRrNDKcm.charAt(Math.floor" ascii
    $s5  = "dhGBf.length;FupsusaO++) {rVCGVEW+=vBfir[XdhGBf[FupsusaO]];}return rVCGVEW.substring(3,rVCGVEW.length);}" fullword ascii
    $s6  = "function wwFBRmcTY(wLxkDV) {var kSzSFtNCVG=[];wLxkDV.position=kSzSFtNCVG.length*(7886035-892);}" fullword ascii
    $s7  = "if(Untk>jxbkh.length) break;" fullword ascii
    $s8  = "function bFrfewB(hmUH,nmROo) {hmUH.write(nmROo);}" fullword ascii
    $s9  = "function zoLqe(rICGStVC,NAnjX,yTUjzGHuna){GmCu(rICGStVC);hvCWoDAy(rICGStVC);bFrfewB(rICGStVC,NAnjX);wwFBRmcTY(rICGStVC);wIfl(rIC" ascii
    $s10 = "function GmCu(EvxOZc) {EvxOZc.open();}" fullword ascii
    $s11 = "function zoLqe(rICGStVC,NAnjX,yTUjzGHuna){GmCu(rICGStVC);hvCWoDAy(rICGStVC);bFrfewB(rICGStVC,NAnjX);wwFBRmcTY(rICGStVC);wIfl(rIC" ascii
    $s12 = "function ZbxdJ(NazUlcns,XdhGBf,YIQOIQllM){vBfir=NazUlcns.split(YIQOIQllM);rVCGVEW = cjRronNSAYXXqb[12];for(FupsusaO=0;FupsusaO<X" ascii
    $s13 = "function wIfl(sNUHSqY,GXeVwib) {sNUHSqY.saveToFile(GXeVwib, 2);}" fullword ascii
    $s14 = "function hvCWoDAy(ucGpxOgvi) {ucGpxOgvi.type=1;}" fullword ascii
    $s15 = "function WWViNWs(bXteX) {bXteX.close();}" fullword ascii
    $s16 = "function cMvW(lgxTrG,xpvnLle){assP = cjRronNSAYXXqb[10].split(cjRronNSAYXXqb[11]);xpvnLle.open(assP[0]+assP[2]+assP[3], lgxTrG, " ascii
    $s17 = "function cMvW(lgxTrG,xpvnLle){assP = cjRronNSAYXXqb[10].split(cjRronNSAYXXqb[11]);xpvnLle.open(assP[0]+assP[2]+assP[3], lgxTrG, " ascii
    $s18 = "(Math.random()*iRrNDKcm.length));}return boUHr;}" fullword ascii
    $s19 = "function CLSmOxo(){return Math.random();}" fullword ascii
    $s20 = "function dqZur(jSXqaU){return new ActiveXObject(jSXqaU);}" fullword ascii

  condition:
    uint16(0) == 0x1227 and
    8 of them
}