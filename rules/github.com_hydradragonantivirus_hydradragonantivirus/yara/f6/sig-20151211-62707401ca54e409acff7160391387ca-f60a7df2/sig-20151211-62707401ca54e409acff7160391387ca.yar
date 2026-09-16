rule sig_20151211_62707401ca54e409acff7160391387ca {
  meta:
    description = "datamaliciousorder - file 20151211_62707401ca54e409acff7160391387ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7f76da237a37f7d8cda57c71d523f9ad9860693c56d88e559467a05a5005801"

  strings:
    $s1  = "function OFxqhAw(RwXpitwhssyypYjChPvYTtOTGSYHLuosqwtr) {return !isNaN(parseFloat(RwXpitwhssyypYjChPvYTtOTGSYHLuosqwtr)) && isFin" ascii
    $s2  = "function OFxqhAw(RwXpitwhssyypYjChPvYTtOTGSYHLuosqwtr) {return !isNaN(parseFloat(RwXpitwhssyypYjChPvYTtOTGSYHLuosqwtr)) && isFin" ascii
    $s3  = "var Y=new Array(\"2a\",\"2a\",\"2d\",\"2d\",\"2f\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s4  = "function lQVihRaPpfuUCZpaT(WKZcu){EVtIdMqhGBl= '';xTMJqgcEhxa=(-843+843)/767; while(true){if(xTMJqgcEhxa >= (395+707)/551)break;" ascii
    $s5  = "var E=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3a\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "function lQVihRaPpfuUCZpaT(WKZcu){EVtIdMqhGBl= '';xTMJqgcEhxa=(-843+843)/767; while(true){if(xTMJqgcEhxa >= (395+707)/551)break;" ascii
    $s7  = "function xOOWrFUzQzbQwyAjFbqiUNABIWKszfMdJaviCHyHrmbkBAgKXkFskO(SLWXXwzAnPZQQ,sbcfHgJAbYOLae){ return YYGLb[dIuMS(SLWXXwzAnPZQQ[" ascii
    $s8  = " ksmGE;}function PLKQRXRROuaPWMA(auvfOMKUHqRhfptbU){eval(auvfOMKUHqRhfptbU)}" fullword ascii
    $s9  = "function xOOWrFUzQzbQwyAjFbqiUNABIWKszfMdJaviCHyHrmbkBAgKXkFskO(SLWXXwzAnPZQQ,sbcfHgJAbYOLae){ return YYGLb[dIuMS(SLWXXwzAnPZQQ[" ascii
    $s10 = "var E=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3a\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "function WonzXFshNFw(anuKPVhs,bqdtmH){return anuKPVhs.split(bqdtmH)}" fullword ascii
    $s12 = "UuYgBebYF[xTMJqgcEhxa]=(-734+734)/395; while(true) { if(UuYgBebYF[xTMJqgcEhxa] > WKZcu[xTMJqgcEhxa].length-(723+140)/863) { brea" ascii
    $s13 = "]++;}xTMJqgcEhxa++;} return EVtIdMqhGBl}" fullword ascii
    $s14 = "var Y=new Array(\"2a\",\"2a\",\"2d\",\"2d\",\"2f\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s15 = "function dIuMS(LryUooJQFyl,AZCAHfMYZnUAa,QCkjCLWT){Isce=parseInt(LryUooJQFyl,AZCAHfMYZnUAa);ksmGE=Isce.toString(QCkjCLWT);return" ascii
    $s16 = "function dIuMS(LryUooJQFyl,AZCAHfMYZnUAa,QCkjCLWT){Isce=parseInt(LryUooJQFyl,AZCAHfMYZnUAa);ksmGE=Isce.toString(QCkjCLWT);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}