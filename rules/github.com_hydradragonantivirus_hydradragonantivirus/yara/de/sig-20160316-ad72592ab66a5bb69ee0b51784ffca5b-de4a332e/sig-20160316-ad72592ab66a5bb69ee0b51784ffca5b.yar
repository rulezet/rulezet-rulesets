rule sig_20160316_ad72592ab66a5bb69ee0b51784ffca5b {
  meta:
    description = "datamaliciousorder - file 20160316_ad72592ab66a5bb69ee0b51784ffca5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba3f7bececcd4897548876ea23dd2d7685b6c2aba9a8d4061e309bef15777c9"

  strings:
    $s1 = "while (pVIBiUja[wbzMFnIovoErA + HibqbYrfYad + KatcFZTkIY + mJGxj + EkPbg + vgHFAURiipr] < 4 ) {WScript[DPXYidzIc + HZkHRuhGjFnB " ascii
    $s2 = "while (pVIBiUja[wbzMFnIovoErA + HibqbYrfYad + KatcFZTkIY + mJGxj + EkPbg + vgHFAURiipr] < 4 ) {WScript[DPXYidzIc + HZkHRuhGjFnB " ascii
    $s3 = "function EuYmqDJVotTD(n){return kdADOkZEnzlHOk + DAxVhtTepNwwSf + aEDJqmw + hqvUDsjrM + yvg + EyPMsbAaoDts + vZeYCwVpXgAT + FmSr" ascii
    $s4 = "pVIBiUja[jNAaSjAsClxeh + mcMzI + rewSqQIKIoZz](NnQIytX + xTy + hjtnyYig, QgOrYDRJmWia + hoe + IrvjWGfBhkulVm + WnmcrSrPGmT + EtT" ascii
    $s5 = "function EuYmqDJVotTD(n){return kdADOkZEnzlHOk + DAxVhtTepNwwSf + aEDJqmw + hqvUDsjrM + yvg + EyPMsbAaoDts + vZeYCwVpXgAT + FmSr" ascii
    $s6 = "lCOqDrRr + qTcBbisqxu + dsvFSdcjfA + eqXvHhIFxvaei, false);" fullword ascii
    $s7 = "var flUX = \"NI\";" fullword ascii
    $s8 = "var yCFCOkeaAFoiNmw = new Date();" fullword ascii
    $s9 = "function mQDUvpUq(uanRnKbrJrOUTk){bJPOgak[hLiA](uanRnKbrJrOUTk, 0, 0);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}