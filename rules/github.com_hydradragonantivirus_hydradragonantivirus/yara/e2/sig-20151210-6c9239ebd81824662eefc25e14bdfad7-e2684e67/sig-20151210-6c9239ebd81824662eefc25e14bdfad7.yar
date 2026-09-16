rule sig_20151210_6c9239ebd81824662eefc25e14bdfad7 {
  meta:
    description = "datamaliciousorder - file 20151210_6c9239ebd81824662eefc25e14bdfad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1c0e3f7f6c961858a844bf71f9c140ae270d71851bc72e2c1b55521249e39f0"

  strings:
    $s1  = "function DqRauLb(JJfFIEKWrRmBdWmMVOdsPqEBFKOFLsOZvTiB) {return !isNaN(parseFloat(JJfFIEKWrRmBdWmMVOdsPqEBFKOFLsOZvTiB)) && isFin" ascii
    $s2  = "function DqRauLb(JJfFIEKWrRmBdWmMVOdsPqEBFKOFLsOZvTiB) {return !isNaN(parseFloat(JJfFIEKWrRmBdWmMVOdsPqEBFKOFLsOZvTiB)) && isFin" ascii
    $s3  = "function QqEviaMIRnkPVmDCX(gokVM){wZOfKgqfNtn= '';for(mbtztDHFPWd=(-96+96)/512; mbtztDHFPWd < (-626+888)/131; mbtztDHFPWd++) {BU" ascii
    $s4  = "VqmvjtN=(-523+523)/816;while(true){if(VqmvjtN>=(55592+856)/441){break;}oOHJJfIvZDBhK[VqmvjtN]=String.fromCharCode(VqmvjtN);Vqmvj" ascii
    $s5  = "function QqEviaMIRnkPVmDCX(gokVM){wZOfKgqfNtn= '';for(mbtztDHFPWd=(-96+96)/512; mbtztDHFPWd < (-626+888)/131; mbtztDHFPWd++) {BU" ascii
    $s6  = "VqmvjtN=(-523+523)/816;while(true){if(VqmvjtN>=(55592+856)/441){break;}oOHJJfIvZDBhK[VqmvjtN]=String.fromCharCode(VqmvjtN);Vqmvj" ascii
    $s7  = "kSxgoDy[mbtztDHFPWd]=(-57+57)/434; while(true) { if(BUkSxgoDy[mbtztDHFPWd] > gokVM[mbtztDHFPWd].length-(407+419)/826) { break; }" ascii
    $s8  = "function KxxJUlbhafpbxotWbohcVORUGKroMMOagzOTceKFUcSyHZSsNKOPpR(yuVocKhiPcxmD,PiakYBPPYChtvM){ return oOHJJfIvZDBhK[sfYOA(yuVocK" ascii
    $s9  = "function RbsTobfHFsI(LlVacCmP,fAVOEB){return LlVacCmP.split(fAVOEB)}" fullword ascii
    $s10 = "}} return wZOfKgqfNtn}" fullword ascii
    $s11 = "function sfYOA(MrgnnELsibo,ycyVmRZwTOvxt,bgnsYBED){cioZ=parseInt(MrgnnELsibo,ycyVmRZwTOvxt);GojXx=cioZ.toString(bgnsYBED);return" ascii
    $s12 = " GojXx;}function AwTWEFKrRIOMxMP(YwzrnmUVMkTjjiqDS){eval(YwzrnmUVMkTjjiqDS)}" fullword ascii
    $s13 = "function sfYOA(MrgnnELsibo,ycyVmRZwTOvxt,bgnsYBED){cioZ=parseInt(MrgnnELsibo,ycyVmRZwTOvxt);GojXx=cioZ.toString(bgnsYBED);return" ascii
    $s14 = "function KxxJUlbhafpbxotWbohcVORUGKroMMOagzOTceKFUcSyHZSsNKOPpR(yuVocKhiPcxmD,PiakYBPPYChtvM){ return oOHJJfIvZDBhK[sfYOA(yuVocK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}