rule sig_20160531_c0aaa08d81f1cff2eea65eb0fa4dd336 {
  meta:
    description = "datamaliciousorder - file 20160531_c0aaa08d81f1cff2eea65eb0fa4dd336.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b05d298a5277670b36361b1ee608940e49857d8f6af90d659697e6359de73327"

  strings:
    $s1  = "var vOUYmmTyXFWc=function(){return WScript.CreateObject(ewMFarpFmoFSiFTpnCjtwzL[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function gZjBtxOpQhNLEN(HerwVkMWWGanE) {var SUzpMHLbTKGyTapV = UtkKtHyq.join(ewMFarpFmoFSiFTpnCjtwzL[7]);var KOLhHXejnUrIZFfB, G" ascii
    $s3  = "function gZjBtxOpQhNLEN(HerwVkMWWGanE) {var SUzpMHLbTKGyTapV = UtkKtHyq.join(ewMFarpFmoFSiFTpnCjtwzL[7]);var KOLhHXejnUrIZFfB, G" ascii
    $s4  = "function emBabfNciipfLyBLiXX(yFuDDblJmOHLTLc,rEryjT){return yFuDDblJmOHLTLc.charAt(rEryjT);}" fullword ascii
    $s5  = "var NLpziTCltXqY=function(){return new ActiveXObject(ewMFarpFmoFSiFTpnCjtwzL[1]);}();" fullword ascii
    $s6  = "function gJYNCFM(){return ILoLvivaejTB(ewMFarpFmoFSiFTpnCjtwzL[11],[2,4,8,10],ewMFarpFmoFSiFTpnCjtwzL[12]);}" fullword ascii
    $s7  = "function OtpUivHmZByRAJ(){return ILoLvivaejTB(ewMFarpFmoFSiFTpnCjtwzL[9],[1,5,7],ewMFarpFmoFSiFTpnCjtwzL[10]);}" fullword ascii
    $s8  = "function ELFxASNWWVWU(){return ILoLvivaejTB(ewMFarpFmoFSiFTpnCjtwzL[13],[0,3,6],ewMFarpFmoFSiFTpnCjtwzL[14]);}" fullword ascii
    $s9  = "function ILoLvivaejTB(IVqZcIFqJHSeFF,AQQLeQXw,kOyahHEbRqbf){tRplBrgG=IVqZcIFqJHSeFF.split(kOyahHEbRqbf);qDpzTSJdf = ewMFarpFmoFS" ascii
    $s10 = "function MorXakDPhYCK(zmnVwBSVUlewn,tRRaXjL) {var RWvtYPaPvYZQ=[ewMFarpFmoFSiFTpnCjtwzL[15]];zmnVwBSVUlewn[RWvtYPaPvYZQ[0]]" fullword ascii
    $s11 = "if (PjNereyrxiFLbKpRcPFjMJO == 64) epABnisfYb += FW(KOLhHXejnUrIZFfB);else if (aPhjYZhf == 64) epABnisfYb += ksNMzeBmSaSZpTJuSmD" ascii
    $s12 = "l(KOLhHXejnUrIZFfB, GtInklIyfmIHmtR);else epABnisfYb += FraZavTUnqR(KOLhHXejnUrIZFfB, GtInklIyfmIHmtR, qoBanAgULCJriq);} while (" ascii
    $s13 = "(tRRaXjL,0x1,0x0)}function qvCfQFoedYDAdc(ynffNBPIvm,jSBoQigLAQQ,UQdbbUIoZqA){var wMtAJWmhyNojFh=ynffNBPIvm.createtextfile(jSBoQ" ascii
    $s14 = "function LfUuhS(){return vOUYmmTyXFWc.ExpandEnvironmentStrings(OtpUivHmZByRAJ())}" fullword ascii
    $s15 = "function ksNMzeBmSaSZpTJuSmDl(dvTrRAwdfKFosSgQAkuvVGP,uJITqxZqTInNpjwRnX){return String.fromCharCode(dvTrRAwdfKFosSgQAkuvVGP,uJI" ascii
    $s16 = "igLAQQ,true);wMtAJWmhyNojFh.WriteLine(UQdbbUIoZqA);wMtAJWmhyNojFh.Close();}" fullword ascii
    $s17 = "GanE,QlSbtftrcyFlyQkmQbdXfGhb++));PjNereyrxiFLbKpRcPFjMJO = QZgzdxB(SUzpMHLbTKGyTapV,emBabfNciipfLyBLiXX(HerwVkMWWGanE,QlSbtftrc" ascii
    $s18 = "function ILoLvivaejTB(IVqZcIFqJHSeFF,AQQLeQXw,kOyahHEbRqbf){tRplBrgG=IVqZcIFqJHSeFF.split(kOyahHEbRqbf);qDpzTSJdf = ewMFarpFmoFS" ascii
    $s19 = "(tRRaXjL,0x1,0x0)}function qvCfQFoedYDAdc(ynffNBPIvm,jSBoQigLAQQ,UQdbbUIoZqA){var wMtAJWmhyNojFh=ynffNBPIvm.createtextfile(jSBoQ" ascii
    $s20 = "function FW(gwuMtprRaCUqB){return String.fromCharCode(gwuMtprRaCUqB);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}