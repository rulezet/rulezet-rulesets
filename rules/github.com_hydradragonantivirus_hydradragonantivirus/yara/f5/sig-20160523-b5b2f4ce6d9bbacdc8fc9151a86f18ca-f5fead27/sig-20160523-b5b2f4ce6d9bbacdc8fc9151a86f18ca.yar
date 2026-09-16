rule sig_20160523_b5b2f4ce6d9bbacdc8fc9151a86f18ca {
  meta:
    description = "datamaliciousorder - file 20160523_b5b2f4ce6d9bbacdc8fc9151a86f18ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a355727bccd62807059986e748fbb7d1d212f7cee6fe5dc19723f916539ac36"

  strings:
    $s1  = "function zpPOgaFUFi(xjiHooBN,EnUsrKaPZLdV) {xjiHooBN.Run(EnUsrKaPZLdV, 0x1, 0x0);}" fullword ascii
    $s2  = "function hJgnHaHf(ziBcb) {var ESqhmkGh=yhuRyhHmIjTUrZ[13];for(var GKkUK=0;GKkUK<ziBcb;GKkUK++){VNLWW+=ESqhmkGh.charAt(Math.floor" ascii
    $s3  = "function hJgnHaHf(ziBcb) {var ESqhmkGh=yhuRyhHmIjTUrZ[13];for(var GKkUK=0;GKkUK<ziBcb;GKkUK++){VNLWW+=ESqhmkGh.charAt(Math.floor" ascii
    $s4  = "jiwpg.length;cbnpMCHL++) {QxMrMqb+=pBcrW[jjiwpg[cbnpMCHL]];}return QxMrMqb.substring(3,QxMrMqb.length);}" fullword ascii
    $s5  = "function kiLcPI(UHzJZF){return UHzJZF.ExpandEnvironmentStrings(yhuRyhHmIjTUrZ[9])}" fullword ascii
    $s6  = "function RteSI(qtDPPWpZ,jjiwpg,MTAlhAGxY){pBcrW=qtDPPWpZ.split(MTAlhAGxY);QxMrMqb = yhuRyhHmIjTUrZ[12];for(cbnpMCHL=0;cbnpMCHL<j" ascii
    $s7  = "function VFSp(rsBfdX) {rsBfdX.open();}" fullword ascii
    $s8  = "function OXvRgdr(){return Math.random();}" fullword ascii
    $s9  = "function QgEzWkRD(EJqoZuZkU) {EJqoZuZkU.type=1;}" fullword ascii
    $s10 = "(Math.random()*ESqhmkGh.length));}return VNLWW;}" fullword ascii
    $s11 = "function NqqVB(qtIiFoaZ,JgjTA,BUiCCtKOOr){VFSp(qtIiFoaZ);QgEzWkRD(qtIiFoaZ);KpxAvmG(qtIiFoaZ,JgjTA);fZaPYgNJZ(qtIiFoaZ);fELr(qtI" ascii
    $s12 = "function dAFghYt() {var kLve=100000;var mCkksQ = 100;return OXvRgdr()*(kLve-mCkksQ)+mCkksQ;}" fullword ascii
    $s13 = "function KpxAvmG(BVoO,jbtCk) {BVoO.write(jbtCk);}" fullword ascii
    $s14 = "false);pQEvuUy.send();}" fullword ascii
    $s15 = "function PHsa(riQeIN,pQEvuUy){EiCh = yhuRyhHmIjTUrZ[10].split(yhuRyhHmIjTUrZ[11]);pQEvuUy.open(EiCh[0]+EiCh[2]+EiCh[3], riQeIN, " ascii
    $s16 = "function fZaPYgNJZ(kUealZ) {var LsIiQTxadV=[];kUealZ.position=LsIiQTxadV.length*(5924784-219);}" fullword ascii
    $s17 = "function PHsa(riQeIN,pQEvuUy){EiCh = yhuRyhHmIjTUrZ[10].split(yhuRyhHmIjTUrZ[11]);pQEvuUy.open(EiCh[0]+EiCh[2]+EiCh[3], riQeIN, " ascii
    $s18 = "function RteSI(qtDPPWpZ,jjiwpg,MTAlhAGxY){pBcrW=qtDPPWpZ.split(MTAlhAGxY);QxMrMqb = yhuRyhHmIjTUrZ[12];for(cbnpMCHL=0;cbnpMCHL<j" ascii
    $s19 = "function dZriwuT(nZKCN) {nZKCN.close();}" fullword ascii
    $s20 = "function tfJCZ(UHzJZF){return new ActiveXObject(UHzJZF);}" fullword ascii

  condition:
    uint16(0) == 0x0427 and
    8 of them
}