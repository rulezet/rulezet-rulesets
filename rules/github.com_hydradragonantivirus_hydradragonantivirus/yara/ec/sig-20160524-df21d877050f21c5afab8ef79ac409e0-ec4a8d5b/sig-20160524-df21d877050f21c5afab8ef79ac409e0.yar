rule sig_20160524_df21d877050f21c5afab8ef79ac409e0 {
  meta:
    description = "datamaliciousorder - file 20160524_df21d877050f21c5afab8ef79ac409e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "212e041e78fdb62acb174932e09cf8dad8db7a307bc6669ea6c664aace4a7477"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = " kWsUsk=function(){return new ActiveXObject(\"WScript.Shell\");}();var qsNFaZI = aABwTCnXgMD[1]+18223+aABwTCnXgMD[2];var dqJdZgr" ascii
    $s3  = "ring.fromCharCode(92) + CGFdUuI;var RhelM = function(){return new ActiveXObject(KSaKW(cDIbofDhIwkn[5],[0,2,4],cDIbofDhIwkn[6]));" ascii
    $s4  = "D.Run(PzYbGduLOdTT, 0x1, 0x0);}function larHTIA() {var Ovsj=100000;var qwOJOa = 100;return syIuVoT()*(Ovsj-qwOJOa)+qwOJOa;}funct" ascii
    $s5  = "{if(CoXn>rsgPZ.length) break;var UaNIoIbWH=rsgPZ[CoXn];var CGFdUuI=larHTIA() + cDIbofDhIwkn[2];var huJCZprn=705-704;var jpLmPGHy" ascii
    $s6  = "y = function(){return new ActiveXObject(KSaKW(cDIbofDhIwkn[3],[0,2,4],cDIbofDhIwkn[4]));}();var CGFdUuI = ixkOWA(jpLmPGHyy) + St" ascii
    $s7  = "ngtYGvsyoJhODwPetFWgZKHgpHAOGXGrQD*/MQNkhQPqOilzT();var rsgPZ = [cDIbofDhIwkn[0], cDIbofDhIwkn[1]];var CoXn=159-159;while(true) " ascii
    $s8  = "\\x50\\x25\"];function YjDUSBsDKBG() {var xMbSQMOjWgtgB;var lEgiBjLExXQ=function(){return new ActiveXObject(aABwTCnXgMD[0]);}();" ascii
    $s9  = "ript;}function cKkPMPiAl(CFfLOy) {var jXRmQgDTGZ=[];CFfLOy.position=jXRmQgDTGZ.length*(2975955-345);}function rTJL(YiEdPmx,mKdRX" ascii
    $s10 = "wArfuG(xEYipLRf);}function QCzn(DpRKnq,OHdyoKM){dPWz = cDIbofDhIwkn[10].split(cDIbofDhIwkn[11]);OHdyoKM.open(dPWz[0]+dPWz[2]+dPW" ascii
    $s11 = "}();QCzn(UaNIoIbWH,RhelM);if (RhelM.status == 100+100) {var VQdmiKb = function() {return new ActiveXObject(KSaKW(cDIbofDhIwkn[7]" ascii
    $s12 = "0x1,0x0);}YjDUSBsDKBG();function (ymOHfpIFq) {return new ActiveXObject(ymOHfpIFq);}" fullword ascii
    $s13 = "JdZgrcStjCd,2,true);xMbSQMOjWgtgB.Write('var cDIbofDhIwkn=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x68\\x6f\\x70\\x2e\\x64" ascii
    $s14 = "hIwkn[12];for(rLkOhAXa=0;rLkOhAXa<oyrgQQ.length;rLkOhAXa++) {thaZtOl+=BHHNG[oyrgQQ[rLkOhAXa]];}return thaZtOl.substring(3,thaZtO" ascii
    $s15 = "andom()*uBtaLcKV.length));}return JRLXn;}function FzlXAyIeYaAwcp(FYseoiYCtZAxnU) {return new ActiveXObject(FYseoiYCtZAxnU);}');v" ascii
    $s16 = "z[3], DpRKnq, false);OHdyoKM.send();}function KSaKW(nIreztLP,oyrgQQ,gJRMDCDeG){BHHNG=nIreztLP.split(gJRMDCDeG);thaZtOl = cDIbofD" ascii
    $s17 = "Zf) {YiEdPmx.saveToFile(mKdRXZf, 2);}function SwArfuG(lIdiL) {lIdiL.close();}function hhyqGTuYKX(oiyFYRBD,PzYbGduLOdTT) {oiyFYRB" ascii
    $s18 = ") {kFXbmj.open();}function AVZcAgoh(DtyYMTvyH) {DtyYMTvyH.type=1;}function twhsdtW(zJEp,gwVmS) {zJEp.write(gwVmS);}function fwbk" ascii
    $s19 = "l.length);}function MQNkhQPqOilzT() {fwbkYGWVkH().Sleep(2566-565);}function syIuVoT(){return Math.random();}function CRLn(kFXbmj" ascii
    $s20 = " catch(e) {}break;};CoXn++;}function ixkOWA(rasNgq){return rasNgq.ExpandEnvironmentStrings(cDIbofDhIwkn[9])}function UYmwr(xEYip" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}