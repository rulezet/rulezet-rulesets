rule sig_20160526_365fd3b6aaf8f05ee0c5321331d567f5 {
  meta:
    description = "datamaliciousorder - file 20160526_365fd3b6aaf8f05ee0c5321331d567f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "623616a08de36e4ec5b36fc81824d232bf82b4d488cf965cca371084a28fec95"

  strings:
    $s1  = "2 + Math.round((Math.pow(Math.sin(131), 2) + Math.pow(Math.cos(131), 2) - 1))-798)) kXQtLdaDKKWPWJ += LC(vZfdlPw);else if (yuVFe" ascii
    $s2  = "function JkeYimTznI(DLUGwKOyMyfPf) {var bvoDaktWxmNGcHSfHwjaM = dzDgQDRdDFqWjWya.join(MZyfbmjKSsuUZjQMRcWB[0]);var vZfdlPw, NfYj" ascii
    $s3  = "function JkeYimTznI(DLUGwKOyMyfPf) {var bvoDaktWxmNGcHSfHwjaM = dzDgQDRdDFqWjWya.join(MZyfbmjKSsuUZjQMRcWB[0]);var vZfdlPw, NfYj" ascii
    $s4  = "function ymWSihevBz(igZMoDgNplb,XBFQRcYIsbhACAtayFl){return igZMoDgNplb.charAt(XBFQRcYIsbhACAtayFl);}" fullword ascii
    $s5  = "function LC(IINKkCmFGGkjEWMHogZXt){return String.fromCharCode(IINKkCmFGGkjEWMHogZXt);}" fullword ascii
    $s6  = "function qsSSIAxfXGJvTPIaVfELD(ceOUHZlp,jyLGPZNqvVJxCEGZfCNjqTdP){return String.fromCharCode(ceOUHZlp,jyLGPZNqvVJxCEGZfCNjqTdP);" ascii
    $s7  = "function qsSSIAxfXGJvTPIaVfELD(ceOUHZlp,jyLGPZNqvVJxCEGZfCNjqTdP){return String.fromCharCode(ceOUHZlp,jyLGPZNqvVJxCEGZfCNjqTdP);" ascii
    $s8  = "function wUOrSqLnFH(sBCQaQnSTQZVqtrqskYEZ,ytdDbLkhvvtlelIn){return sBCQaQnSTQZVqtrqskYEZ.indexOf(ytdDbLkhvvtlelIn);}" fullword ascii
    $s9  = "LQpQkrTpmsDZ < DLUGwKOyMyfPf.length);return kXQtLdaDKKWPWJ;}" fullword ascii
    $s10 = "function UptMYJyeGJcCiCaafqvdMC(qrfhwQxQQAVVFDkND,xnrJlJEEYwPG,hhIvmllJSFieyf){return String.fromCharCode(qrfhwQxQQAVVFDkND,xnrJ" ascii
    $s11 = "function UptMYJyeGJcCiCaafqvdMC(qrfhwQxQQAVVFDkND,xnrJlJEEYwPG,hhIvmllJSFieyf){return String.fromCharCode(qrfhwQxQQAVVFDkND,xnrJ" ascii
    $s12 = "TPIaVfELD(vZfdlPw, NfYjsVhpArToxxHDS);else kXQtLdaDKKWPWJ += UptMYJyeGJcCiCaafqvdMC(vZfdlPw, NfYjsVhpArToxxHDS, JAjlV);} while (" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}