rule sig_20151210_fdcff6c4b2aa22278a07e6af4687727a {
  meta:
    description = "datamaliciousorder - file 20151210_fdcff6c4b2aa22278a07e6af4687727a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d9bdbcb9978c09318c2acaa4cd36c86ee55cd7fdeffdedf866a4dea8ec9247b"

  strings:
    $s1  = "function Csbmcyf(cZvyDClekrYtlCmWGyLRfDrTAZkOAxLvkWWz) {return !isNaN(parseFloat(cZvyDClekrYtlCmWGyLRfDrTAZkOAxLvkWWz)) && isFin" ascii
    $s2  = "function Csbmcyf(cZvyDClekrYtlCmWGyLRfDrTAZkOAxLvkWWz) {return !isNaN(parseFloat(cZvyDClekrYtlCmWGyLRfDrTAZkOAxLvkWWz)) && isFin" ascii
    $s3  = "TRVmKEtt[MnPAWWuyllo]=(-709+709)/703; while(true) { if(hTRVmKEtt[MnPAWWuyllo] > MEpUR[MnPAWWuyllo].length-(-437+915)/478) { brea" ascii
    $s4  = "hjlOqDe=(-974+974)/499;while(true){if(hjlOqDe>=(82008+808)/647){break;}SyGJyChDhLLml[hjlOqDe]=String.fromCharCode(hjlOqDe);hjlOq" ascii
    $s5  = "function wuVjlOkcEtrbdenIiXwomIjvxgMnUIxbYbHprYOXTVynrFvmkPdZpt(tGbeimXvIVWUJ,YPznhsAcQetAwP){ return SyGJyChDhLLml[HpKTS(tGbeim" ascii
    $s6  = "function MeKyEklVbTv(vczsTjhJ,dUepSt){return vczsTjhJ.split(dUepSt)}" fullword ascii
    $s7  = "hjlOqDe=(-974+974)/499;while(true){if(hjlOqDe>=(82008+808)/647){break;}SyGJyChDhLLml[hjlOqDe]=String.fromCharCode(hjlOqDe);hjlOq" ascii
    $s8  = "function HpKTS(qKJfbtakvuu,LIuNCSzPwTczH,cSmevAjl){ShRa=parseInt(qKJfbtakvuu,LIuNCSzPwTczH);mfUSF=ShRa.toString(cSmevAjl);return" ascii
    $s9  = " mfUSF;}function TCLOAgjVqFtajQd(AdXkmiIVnapQqDRfV){eval(AdXkmiIVnapQqDRfV)}" fullword ascii
    $s10 = "function wuVjlOkcEtrbdenIiXwomIjvxgMnUIxbYbHprYOXTVynrFvmkPdZpt(tGbeimXvIVWUJ,YPznhsAcQetAwP){ return SyGJyChDhLLml[HpKTS(tGbeim" ascii
    $s11 = "function AJDrbWMINZRItGydV(MEpUR){KqAFkivRQTO= '';for(MnPAWWuyllo=(-923+923)/173; MnPAWWuyllo < (-64+666)/301; MnPAWWuyllo++) {h" ascii
    $s12 = "function HpKTS(qKJfbtakvuu,LIuNCSzPwTczH,cSmevAjl){ShRa=parseInt(qKJfbtakvuu,LIuNCSzPwTczH);mfUSF=ShRa.toString(cSmevAjl);return" ascii
    $s13 = "++;}} return KqAFkivRQTO}" fullword ascii
    $s14 = "function AJDrbWMINZRItGydV(MEpUR){KqAFkivRQTO= '';for(MnPAWWuyllo=(-923+923)/173; MnPAWWuyllo < (-64+666)/301; MnPAWWuyllo++) {h" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}