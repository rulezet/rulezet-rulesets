rule sig_20151211_b9146d057eff86fd38ca1a6aed1964ff {
  meta:
    description = "datamaliciousorder - file 20151211_b9146d057eff86fd38ca1a6aed1964ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c0ae26022f218a5d6a14e9e791ee8b621204ce058cb49408cc68a5ac0480e69"

  strings:
    $s1  = "function Gtseoly(wcVjAcfvlHoXtGWIACxWpvoEmlRkaPfAhHzz) {return !isNaN(parseFloat(wcVjAcfvlHoXtGWIACxWpvoEmlRkaPfAhHzz)) && isFin" ascii
    $s2  = "function Gtseoly(wcVjAcfvlHoXtGWIACxWpvoEmlRkaPfAhHzz) {return !isNaN(parseFloat(wcVjAcfvlHoXtGWIACxWpvoEmlRkaPfAhHzz)) && isFin" ascii
    $s3  = "function etoPJhZwlFWbYOxiPiBpKrGbGkGjKhvSTjHGjLKHrHkNofShlbYSdo(qAaJXLxybNAEq,bzDaumkaijvAdO){ return ndNja[vPvGa(qAaJXLxybNAEq[" ascii
    $s4  = "function hTkKEqmFmiBSNKTSw(EJIyF){UJIQDCRMmoq= '';YAjDNWURUXC=(-615+615)/611; while(true){if(YAjDNWURUXC >= (962+946)/954)break;" ascii
    $s5  = "function etoPJhZwlFWbYOxiPiBpKrGbGkGjKhvSTjHGjLKHrHkNofShlbYSdo(qAaJXLxybNAEq,bzDaumkaijvAdO){ return ndNja[vPvGa(qAaJXLxybNAEq[" ascii
    $s6  = "var n=new Array(\"29\",\"29\",\"29\",\"2f\",\"2d\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s7  = ";}YAjDNWURUXC++;} return UJIQDCRMmoq}" fullword ascii
    $s8  = "var n=new Array(\"29\",\"29\",\"29\",\"2f\",\"2d\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s9  = "var y=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3i\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = "pqmugJRHT[YAjDNWURUXC]=(-110+110)/67; while(true) { if(pqmugJRHT[YAjDNWURUXC] > EJIyF[YAjDNWURUXC].length-(267+442)/709) { break" ascii
    $s11 = "var y=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3i\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "function vPvGa(QNvkapIrZVm,fZlpviNvSxOGC,tfKrmNkb){jwTf=parseInt(QNvkapIrZVm,fZlpviNvSxOGC);kXKYy=jwTf.toString(tfKrmNkb);return" ascii
    $s13 = "function hTkKEqmFmiBSNKTSw(EJIyF){UJIQDCRMmoq= '';YAjDNWURUXC=(-615+615)/611; while(true){if(YAjDNWURUXC >= (962+946)/954)break;" ascii
    $s14 = "function JKNGhzxJpba(eWbEjTTj,KmAvGl){return eWbEjTTj.split(KmAvGl)}" fullword ascii
    $s15 = "function vPvGa(QNvkapIrZVm,fZlpviNvSxOGC,tfKrmNkb){jwTf=parseInt(QNvkapIrZVm,fZlpviNvSxOGC);kXKYy=jwTf.toString(tfKrmNkb);return" ascii
    $s16 = " kXKYy;}function NHGFdivJtnEjTvp(XUOGvzJCArbMVmyZU){eval(XUOGvzJCArbMVmyZU)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}