rule sig_20160526_7ead966cb83ef425d6f9b818a79d7463 {
  meta:
    description = "datamaliciousorder - file 20160526_7ead966cb83ef425d6f9b818a79d7463.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bea57702b1230e427ee1f226a5ba79c097aa7de5df533e3e6b61a2cb6f427829"

  strings:
    $s1  = "function GSBhp(onMhcCKXLlInE) {var LZGatqMzH = XzSUGZj.join(EeDdrjUHtQ[0]);var YJhXaihOEJPxXVWaAOY, AjVqqtifxeb, gZSSWn, GOhHLAd" ascii
    $s2  = "Y);else if (NFLWjrkGmwAkhTNI == (193 + Math.round((Math.pow(Math.sin(266), 2) + Math.pow(Math.cos(266), 2) - 1))-129)) eheBKmbvK" ascii
    $s3  = "function xzyNzYsyqQRtf(KoFLgGmqMHkyfKmziqRhbQML,vgSlWoYkIAZzsmCgXEvUAIM){return KoFLgGmqMHkyfKmziqRhbQML.charAt(vgSlWoYkIAZzsmCg" ascii
    $s4  = "function xzyNzYsyqQRtf(KoFLgGmqMHkyfKmziqRhbQML,vgSlWoYkIAZzsmCgXEvUAIM){return KoFLgGmqMHkyfKmziqRhbQML.charAt(vgSlWoYkIAZzsmCg" ascii
    $s5  = "function GSBhp(onMhcCKXLlInE) {var LZGatqMzH = XzSUGZj.join(EeDdrjUHtQ[0]);var YJhXaihOEJPxXVWaAOY, AjVqqtifxeb, gZSSWn, GOhHLAd" ascii
    $s6  = "function AZ(GJaTbpPvBzm){return String.fromCharCode(GJaTbpPvBzm);}" fullword ascii
    $s7  = "function kIvObfIGDMdZyCDjJpkjt(DPbolBPAJNqsDlYNpn,XGdMumRiiIJAHTjV){return String.fromCharCode(DPbolBPAJNqsDlYNpn,XGdMumRiiIJAHT" ascii
    $s8  = "EJPxXVWaAOY, AjVqqtifxeb, gZSSWn);} while (ZdOpoeuwyQgG < onMhcCKXLlInE.length);return eheBKmbvKdAnGAjaZrxb;}" fullword ascii
    $s9  = "function yEFksFVKQXnXYMbgixE(oHWvkyrURnXPnVvlvGLbrh,MYKsEGLVvVyhIRnTs,IxAhuBJNtQckyxOYxLjtYIw){return String.fromCharCode(oHWvky" ascii
    $s10 = "dAnGAjaZrxb += kIvObfIGDMdZyCDjJpkjt(YJhXaihOEJPxXVWaAOY, AjVqqtifxeb);else eheBKmbvKdAnGAjaZrxb += yEFksFVKQXnXYMbgixE(YJhXaihO" ascii
    $s11 = "function kxbOmloUYTfgsdxYNte(lnHBCdC,VZOpxTqKps){return lnHBCdC.indexOf(VZOpxTqKps);}" fullword ascii
    $s12 = "function kIvObfIGDMdZyCDjJpkjt(DPbolBPAJNqsDlYNpn,XGdMumRiiIJAHTjV){return String.fromCharCode(DPbolBPAJNqsDlYNpn,XGdMumRiiIJAHT" ascii
    $s13 = "function yEFksFVKQXnXYMbgixE(oHWvkyrURnXPnVvlvGLbrh,MYKsEGLVvVyhIRnTs,IxAhuBJNtQckyxOYxLjtYIw){return String.fromCharCode(oHWvky" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}