rule sig_20160520_83f041de5a0d05d183a92538f441548f {
  meta:
    description = "datamaliciousorder - file 20160520_83f041de5a0d05d183a92538f441548f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1be9b324956e7ed36c3557febea4ebf61fdc4cb2ab8a41dc2d413a363251a51"

  strings:
    $s1  = "function LiyKfcwn(vkarS) {var ygAikoTB=EsfjQOflqGauHGzJCrVvioNW[2];for(var mwbKV=0;mwbKV<vkarS;mwbKV++){cdUef+=ygAikoTB.charAt(M" ascii
    $s2  = "function LiyKfcwn(vkarS) {var ygAikoTB=EsfjQOflqGauHGzJCrVvioNW[2];for(var mwbKV=0;mwbKV<vkarS;mwbKV++){cdUef+=ygAikoTB.charAt(M" ascii
    $s3  = "ath.floor(Math.random()*ygAikoTB.length));}return cdUef;}" fullword ascii
    $s4  = "try{HbCMIPQ=IJNUUlxdu(PIXpD[nIrz], IAZGfvl() + EsfjQOflqGauHGzJCrVvioNW[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function SoMcp(FtcSOyeE,bTfgdW,FBgyBvVSt){stWze=FtcSOyeE.split(FBgyBvVSt);pdGMboA = EsfjQOflqGauHGzJCrVvioNW[13];for(TIVdzeZg=0;" ascii
    $s6  = "function qnjfF(VqKqsCqI,uQAtv,GvHlWFljli){VqKqsCqI.open();VqKqsCqI.type = 1;VqKqsCqI.write(uQAtv);VqKqsCqI.position = 0;VqKqsCqI" ascii
    $s7  = "2]+kAZh[3], HvcqvT, false);bEsSSGK.send();}" fullword ascii
    $s8  = "function qgwK(HvcqvT,bEsSSGK){kAZh = EsfjQOflqGauHGzJCrVvioNW[11].split(EsfjQOflqGauHGzJCrVvioNW[12]);bEsSSGK.open(kAZh[0]+kAZh[" ascii
    $s9  = "function qgwK(HvcqvT,bEsSSGK){kAZh = EsfjQOflqGauHGzJCrVvioNW[11].split(EsfjQOflqGauHGzJCrVvioNW[12]);bEsSSGK.open(kAZh[0]+kAZh[" ascii
    $s10 = "function qnjfF(VqKqsCqI,uQAtv,GvHlWFljli){VqKqsCqI.open();VqKqsCqI.type = 1;VqKqsCqI.write(uQAtv);VqKqsCqI.position = 0;VqKqsCqI" ascii
    $s11 = "function khlft(AYavzW){return new ActiveXObject(AYavzW);}" fullword ascii
    $s12 = "if (HbCMIPQ==0) break;" fullword ascii
    $s13 = "function IJNUUlxdu(bBGRSWScq,fqyaNtC,afRmVTea){" fullword ascii
    $s14 = "function LuoXiV(AYavzW){return AYavzW.ExpandEnvironmentStrings(EsfjQOflqGauHGzJCrVvioNW[10])}" fullword ascii
    $s15 = "function SoMcp(FtcSOyeE,bTfgdW,FBgyBvVSt){stWze=FtcSOyeE.split(FBgyBvVSt);pdGMboA = EsfjQOflqGauHGzJCrVvioNW[13];for(TIVdzeZg=0;" ascii
    $s16 = "TIVdzeZg<bTfgdW.length;TIVdzeZg++) {pdGMboA+=stWze[bTfgdW[TIVdzeZg]];}return pdGMboA.substring(3,pdGMboA.length);}" fullword ascii
    $s17 = "function IAZGfvl() {var VErs=100000;var VkClFC = 100;return Math.random()*(VErs-VkClFC)+VkClFC;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}