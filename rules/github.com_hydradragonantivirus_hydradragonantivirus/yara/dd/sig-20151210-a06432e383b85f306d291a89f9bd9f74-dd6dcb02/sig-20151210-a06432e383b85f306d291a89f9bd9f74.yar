rule sig_20151210_a06432e383b85f306d291a89f9bd9f74 {
  meta:
    description = "datamaliciousorder - file 20151210_a06432e383b85f306d291a89f9bd9f74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e352838cd6c270c044bc7f4a8fc6dca9d466dd5538d22178e444a29b4c6581a"

  strings:
    $s1  = "function qkerJWm(FcgRIYQAjLWpyHvpOlUNXhEfFjuwVPGvYlif) {return !isNaN(parseFloat(FcgRIYQAjLWpyHvpOlUNXhEfFjuwVPGvYlif)) && isFin" ascii
    $s2  = "function qkerJWm(FcgRIYQAjLWpyHvpOlUNXhEfFjuwVPGvYlif) {return !isNaN(parseFloat(FcgRIYQAjLWpyHvpOlUNXhEfFjuwVPGvYlif)) && isFin" ascii
    $s3  = "JEcN[QvYVkNflMxx]=(-806+806)/141; while(true) { if(MACnPJEcN[QvYVkNflMxx] > lTeHe[QvYVkNflMxx].length-(73+154)/227) { break; } i" ascii
    $s4  = "function idrhkoVIrkGtjiwpyTzPvRNmnhNxIurInszUHSGspUYCyiouJMElba(BQZVLbshVYdih,QXfjKQoubkyRfH){ return RvIAG[gdegv(BQZVLbshVYdih[" ascii
    $s5  = "function gdegv(AIdZIyTrxss,xTfEOScsywfmh,poPSzrDd){bptd=parseInt(AIdZIyTrxss,xTfEOScsywfmh);lTxRD=bptd.toString(poPSzrDd);return" ascii
    $s6  = "function gdegv(AIdZIyTrxss,xTfEOScsywfmh,poPSzrDd){bptd=parseInt(AIdZIyTrxss,xTfEOScsywfmh);lTxRD=bptd.toString(poPSzrDd);return" ascii
    $s7  = " lTxRD;}function JYXbzyZtOSUFxbs(RddoGkkaNvaPGmyGE){eval(RddoGkkaNvaPGmyGE)}" fullword ascii
    $s8  = "function UUptzoLNObKQixEWw(lTeHe){GWHObXvwGaJ= '';for(QvYVkNflMxx=(-9+9)/753; QvYVkNflMxx < (1254+52)/653; QvYVkNflMxx++) {MACnP" ascii
    $s9  = "function UUptzoLNObKQixEWw(lTeHe){GWHObXvwGaJ= '';for(QvYVkNflMxx=(-9+9)/753; QvYVkNflMxx < (1254+52)/653; QvYVkNflMxx++) {MACnP" ascii
    $s10 = "function idrhkoVIrkGtjiwpyTzPvRNmnhNxIurInszUHSGspUYCyiouJMElba(BQZVLbshVYdih,QXfjKQoubkyRfH){ return RvIAG[gdegv(BQZVLbshVYdih[" ascii
    $s11 = "function YCzDjTZBjVD(hzwlBsOJ,GnupMQ){return hzwlBsOJ.split(GnupMQ)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}