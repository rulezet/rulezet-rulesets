rule sig_20160506_36278f89b68d2085ddf5acbd79849c27 {
  meta:
    description = "datamaliciousorder - file 20160506_36278f89b68d2085ddf5acbd79849c27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c047c41bb783a7da4ff601560583128d60f0c01030b3221d1305551340390c1"

  strings:
    $x1  = "function A0J(B, y){var Ws = 0;if(Math.asin(Ws) != 0){ES0 = \"41648\";}else{pFF = -63649;}try{var cC = 0xa8ef;}catch(WaE){var Vk " ascii
    $s2  = "'';}function W(yC){return Math.log(yC);}var PE9 = \"\";var dj0 = \"22514\";if(PE9 === dj0){APF = 31846;}else{CUh = \"28dc6b\";}i" ascii
    $s3  = "m2J) != 0){YK = \"\\x32\\x34\\x31\\x39\\x35\\x31\\x31\\x39\";}function fVk(zfi){return Math.log(zfi);}if(\"\\x33\\x35\\x34\\x33" ascii
    $s4  = "t(-45960);}if(\"62846\".indexOf(\"3183\") == 0){wL = false;}var jKu = Math.floor(Math.random() * 65536);if(0xffff6d2f >= -4581){" ascii
    $s5  = "Xk = \"\\x36\\x64\\x32\\x66\";}else{var C7 = 'passwords';}for(Xi = 0; Xi < ML.length; Xi++){var YYF = \"39971\";if(YYF === \"-30" ascii
    $s6  = "130162){Z4Z = \"operator\";}var mW = 0;if(Math.cos(mW) === 0){var eS = '-10417';}else{var Q4s = \"\";}if(THZ == 0){var GR5 = 0;i" ascii
    $s7  = "{return Math.atan2(pRi, EL);}if(\"\".indexOf(\"\") == -1){var sP = false;}function sb(Sxc){return Math.asin(Sxc);}J = J + 1;var " ascii
    $s8  = ".sin(gfB) == 0){WQ = 'posted';}if(\"6ead95f\".indexOf(\"48456\") > 0){var Cp = true;}else{ynt = false;}var ui = 1;if(Math.cos(ui" ascii
    $s9  = " parseInt(64365, 8);}if(\"40ce06f\".length < parseInt(-5314)){Ljk = true;}var rZ = 0;if(Math.sin(rZ) >= 0){wJU = -34789;}else{Fb" ascii
    $s10 = " = true;}else{var AL = \"\";}var SQj = -1;if(Math.cos(SQj) == 0){var WA1 = true;}if(\"-24906\".length > -8086){var Wbw = 0x2990;" ascii
    $s11 = ".lastIndexOf(\"\") == 0){SV = -18566;}var yqf = 1;if(Math.sin(yqf) == 0){var F = false;}else{var ul = false;}var rw = -1;if(Math" ascii
    $s12 = "var UM6 = oZ(\"2b01350456\", \"HmZw39W\");function moC(zV){return Math.tan(zV);}if(\"findings\".indexOf(\"21417\") == -1){var zw" ascii
    $s13 = "1;if(Math.acos(Qyg) != 0){var S8E = true;}else{var tGy = 'hawaiian';}if(J >= d.length){var boP = -1;if(Math.sin(boP) == 0){var F" ascii
    $s14 = ";}var jKu = cuN();if(\"\".indexOf(\"\\x31\\x65\\x32\\x39\") < 0){_3 = false;}var WX = -1;if(Math.sin(WX) > 0){ZVX = \"\\x63\\x66" ascii
    $s15 = ");}if(\"27028\".indexOf(\"-30032\") != -1){RnP = true;}var MX = 1;if(Math.cos(MX) >= 0){KCk = 0xffff1c14;}else{Mj = '';}if(\"wit" ascii
    $s16 = "1\\x62\\x63\\x65\\x63\\x33\\x63\".indexOf(\"6b34a8\") == -1){var VO = true;}var JqJ = 0;if(Math.cos(JqJ) == 0){var bg = -49063;}" ascii
    $s17 = ") > 0){jO = '-20221';}else{var hrw = -20836;}var g_u = 1;if(Math.cos(g_u) != 0){w44 = \"15408\";}if(\"845\".indexOf(\"\") < 0){c" ascii
    $s18 = "{LYP = -12454;}var t35 = 1;if(Math.cos(t35) === 0){Z80 = true;}else{vTY = parseInt(11463);}var pPA = 1;if(Math.acos(pPA) > 0){Ky" ascii
    $s19 = "';}var _n = 0;if(Math.sin(_n) != 0){var dKH = 0116532;}else{var njS = \"\";}var ZKd = -1;if(Math.cos(ZKd) === 0){ho = '-44576';}" ascii
    $s20 = "ion UXs(){if(\"-47747\".length < -17316){var eC = 0x6186;}else{wb = 0xb0c1;}var aK = -1;if(Math.sin(aK) == 0){s3 = \"\\x61\\x37" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}