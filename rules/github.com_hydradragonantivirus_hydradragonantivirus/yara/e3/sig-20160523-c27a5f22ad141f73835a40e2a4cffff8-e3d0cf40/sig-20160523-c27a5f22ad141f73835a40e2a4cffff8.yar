rule sig_20160523_c27a5f22ad141f73835a40e2a4cffff8 {
  meta:
    description = "datamaliciousorder - file 20160523_c27a5f22ad141f73835a40e2a4cffff8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e3e617957433d697e9f0a21810a2be34874f39ed625ebb9684baf4e56d6faa4"

  strings:
    $s1  = "function rrTcsIiM(sgGiv) {var YyBINqkb=PiwbCxuShmOp[13];for(var wgThw=0;wgThw<sgGiv;wgThw++){YzohB+=YyBINqkb.charAt(Math.floor(M" ascii
    $s2  = "function rrTcsIiM(sgGiv) {var YyBINqkb=PiwbCxuShmOp[13];for(var wgThw=0;wgThw<sgGiv;wgThw++){YzohB+=YyBINqkb.charAt(Math.floor(M" ascii
    $s3  = "function usLsmUQtWt(KrvnfrdC,FdaYBPjjiukG) {KrvnfrdC.Run(FdaYBPjjiukG, 0x1, 0x0);}" fullword ascii
    $s4  = "function seHItFpoTL() {return/*bdaNfVxXsgrAjiVVDZYFuZSybGRezNjHnLlXTfQKIrYDvlsRBeTKAbdzdYfgfMQnAXOUbkqzzWGhoNpByBXLEQZunuxlWaDsJ" ascii
    $s5  = "ath.random()*YyBINqkb.length));}return YzohB;}" fullword ascii
    $s6  = "xng.length;bfOLmwPo++) {BYbVume+=AQift[jhMxng[bfOLmwPo]];}return BYbVume.substring(3,BYbVume.length);}" fullword ascii
    $s7  = "function pDmztet(){return Math.random();}" fullword ascii
    $s8  = "function Xdbp(mhYsDw) {mhYsDw.open();}" fullword ascii
    $s9  = "if(qhhK>VhMRN.length) break;" fullword ascii
    $s10 = "function TbICR(BVqlyDXL,gVrVM,hXHgOLrttW){Xdbp(BVqlyDXL);kFsjYMNd(BVqlyDXL);vUHBOXj(BVqlyDXL,gVrVM);ZFHQbVjHe(BVqlyDXL);ljCF(BVq" ascii
    $s11 = "function CdAkKl(EPUIEl){return EPUIEl.ExpandEnvironmentStrings(PiwbCxuShmOp[9])}" fullword ascii
    $s12 = "function ljCF(OhhXkSd,hwGqRWB) {OhhXkSd.saveToFile(hwGqRWB, 2);}" fullword ascii
    $s13 = "function jIOWb(Baltcsue,jhMxng,UlGdZmrum){AQift=Baltcsue.split(UlGdZmrum);BYbVume = PiwbCxuShmOp[12];for(bfOLmwPo=0;bfOLmwPo<jhM" ascii
    $s14 = "function seHItFpoTL() {return/*bdaNfVxXsgrAjiVVDZYFuZSybGRezNjHnLlXTfQKIrYDvlsRBeTKAbdzdYfgfMQnAXOUbkqzzWGhoNpByBXLEQZunuxlWaDsJ" ascii
    $s15 = "function jIOWb(Baltcsue,jhMxng,UlGdZmrum){AQift=Baltcsue.split(UlGdZmrum);BYbVume = PiwbCxuShmOp[12];for(bfOLmwPo=0;bfOLmwPo<jhM" ascii
    $s16 = "function WxCjZzI(gumtM) {gumtM.close();}" fullword ascii
    $s17 = "function TROid(EPUIEl){return new ActiveXObject(EPUIEl);}" fullword ascii
    $s18 = "function ZFHQbVjHe(PovPgw) {var KJZeZExCRR=[];PovPgw.position=KJZeZExCRR.length*(5452008-881);}" fullword ascii
    $s19 = "function kFsjYMNd(HpUTBHiEY) {HpUTBHiEY.type=1;}" fullword ascii
    $s20 = "function zcCw(gdSdMd,wMgklcE){hxUs = PiwbCxuShmOp[10].split(PiwbCxuShmOp[11]);wMgklcE.open(hxUs[0]+hxUs[2]+hxUs[3], gdSdMd, fals" ascii

  condition:
    uint16(0) == 0x1327 and
    8 of them
}