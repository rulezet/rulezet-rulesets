rule sig_20160524_d0ddeeaf2cc80bd2d5ddc481802baf1f {
  meta:
    description = "datamaliciousorder - file 20160524_d0ddeeaf2cc80bd2d5ddc481802baf1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "528bfc45c722ffa6baf7be8a748f309856cce39d75c51bdefa3436a8cdb1612a"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "rn/*vGQsZwVrlSdVPmNjXwWNvNeKteiFDMIElEBmcWlHmIMuDeBEkdEQUXrjREOoOoujVVfAYQvqiRpnkqktrefonBydjwoqSjZhyGDhNdztW*/WScript;}function" ascii
    $s3  = "aveToFile(CUROure, 2);}function UJPAeon(LdAkR) {LdAkR.close();}function dmDuPPRCyc(YRQqyudw,nQVORiEiicPX) {YRQqyudw.Run(nQVORiEi" ascii
    $s4  = "d[QRgD];var jhWNvtt=pUgLNST() + ijiZSxJmOHQjVbd[2];var VTOdDWSd=692-691;var VvCYKHqUf = function(){return new ActiveXObject(IAeY" ascii
    $s5  = "Mna.status == 100+100) {var azbSuEk = function() {return new ActiveXObject(IAeYV(ijiZSxJmOHQjVbd[7],[0,2,4],ijiZSxJmOHQjVbd[8]))" ascii
    $s6  = "OqvIc.length));}return XrPMf;}function UdoeRryoUMlEQE(aeQMOsGCbAwRKi) {return new ActiveXObject(aeQMOsGCbAwRKi);}');var euexcRxV" ascii
    $s7  = "5\\x63\\x74\",\"\\x47\\x67\\x56\\x6b\\x73\\x73\\x71\\x51\\x42\\x55\\x62\\x64\\x49\\x6b\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45" ascii
    $s8  = "ction uLyLVMBrzAezy() {KDOYwqmEQt().Sleep(4687-558);}function QRRQagw(){return Math.random();}function WRio(lUJKio) {lUJKio.open" ascii
    $s9  = "icPX, 0x1, 0x0);}function pUgLNST() {var LrCW=100000;var ilOlHi = 100;return QRRQagw()*(LrCW-ilOlHi)+ilOlHi;}function VmnsOWFC(M" ascii
    $s10 = "();}function VCLDDjtS(SvfMzFsrK) {SvfMzFsrK.type=1;}function FeklNPy(nUxJ,AsAZl) {nUxJ.write(AsAZl);}function KDOYwqmEQt() {retu" ascii
    $s11 = "ar imoid = [ijiZSxJmOHQjVbd[0], ijiZSxJmOHQjVbd[1]];var QRgD=299-299;while(true) {if(QRgD>imoid.length) break;var xETQzsgfr=imoi" ascii
    $s12 = "XcSzMvJW=0;XcSzMvJW<WtVEcu.length;XcSzMvJW++) {CwvkzPh+=yyuCU[WtVEcu[XcSzMvJW]];}return CwvkzPh.substring(3,CwvkzPh.length);}fun" ascii
    $s13 = "0x0);}juaQQKD();function (zKJbLrIWqVmZzs) {return new ActiveXObject(zKJbLrIWqVmZzs);}" fullword ascii
    $s14 = "Mna = function(){return new ActiveXObject(IAeYV(ijiZSxJmOHQjVbd[5],[0,2,4],ijiZSxJmOHQjVbd[6]));}();OnIc(xETQzsgfr,gSMna);if (gS" ascii
    $s15 = " aWXfjkItL(oLNXHm) {var xNmOkxDxlT=[];oLNXHm.position=xNmOkxDxlT.length*(4325418-617);}function DSlu(MevRaKB,CUROure) {MevRaKB.s" ascii
    $s16 = ";}function xqCryp(UPnXOv){return UPnXOv.ExpandEnvironmentStrings(ijiZSxJmOHQjVbd[9])}function WhfCE(ZzgQAivy,GNgVS,tyYhEjYXyy){Z" ascii
    $s17 = "se);OxYstlw.send();}function IAeYV(NWVeptsv,WtVEcu,IRxwjTzVF){yyuCU=NWVeptsv.split(IRxwjTzVF);CwvkzPh = ijiZSxJmOHQjVbd[12];for(" ascii
    $s18 = "e(NgDegWt,2,true);ErBIcqlOdKZ.Write('var ijiZSxJmOHQjVbd=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x62\\x61\\x67\\x6e\\x69\\x66\\x" ascii
    $s19 = "D() {var ErBIcqlOdKZ;var wjRrFKS=function(){return new ActiveXObject(vTWYQmvAhtNtPuvsRPNsjVld[0]);}();var YXoalJB=function(){ret" ascii
    $s20 = ";}();WhfCE(azbSuEk,gSMna.ResponseBody,jhWNvtt);}if (VTOdDWSd > 0){try {dmDuPPRCyc(VvCYKHqUf,jhWNvtt);} catch(e) {}break;};QRgD++" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}