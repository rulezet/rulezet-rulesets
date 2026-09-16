rule sig_20161117_80d89caa5fcd079e76d148eba1b56f36 {
  meta:
    description = "datamaliciousorder - file 20161117_80d89caa5fcd079e76d148eba1b56f36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40679f44e4d62b42b621a3450f51b5fa5a706796cbe2d203e1dc128fa4d511e8"

  strings:
    $s1  = "while(Uf8CHby['' + ('BNqT', 'F_ho', 'RegWe', 'WsP1', 'ryr96'.T()) + 'e' + ('TotfH', 'ZGIis', 'aWP'.T()) + ('s0m9', 'f22c', 'naJ'" ascii
    $s2  = "function String.prototype.T(){var IGjAFB=(((11173888>>12)>>>(0x3<<32))%(~-2));var YAitH3zp=this.split('');if (Number(dqo3wgI[-1+" ascii
    $s3  = "while(Uf8CHby['' + ('BNqT', 'F_ho', 'RegWe', 'WsP1', 'ryr96'.T()) + 'e' + ('TotfH', 'ZGIis', 'aWP'.T()) + ('s0m9', 'f22c', 'naJ'" ascii
    $s4  = "while(qMAXPR0P==(((7602176>>0x8)>>>(2359296>>>0x12))%(0x800>>0xb))){Uf8CHby['' + ('MWYC', 'X7n', 'oNCWG'.T()) + ('PxoO', '_MQgF'" ascii
    $s5  = "dqo3wgI=[];var kaeQdyZFeMyX=\" \";ULW71j=ULW71j+new Date();while(FZAQEP6qZ>(((0x3e*0x3+3)<<(1<<5))%(0x1<<0x20))){zHFVXw=ULW71j.s" ascii
    $s6  = "while(qMAXPR0P==(((7602176>>0x8)>>>(2359296>>>0x12))%(0x800>>0xb))){Uf8CHby['' + ('MWYC', 'X7n', 'oNCWG'.T()) + ('PxoO', '_MQgF'" ascii
    $s7  = "function String.prototype.T(){var IGjAFB=(((11173888>>12)>>>(0x3<<32))%(~-2));var YAitH3zp=this.split('');if (Number(dqo3wgI[-1+" ascii
    $s8  = "7425)>>(0xc*0x1+0x1))>>>(4*0x1+2))) IGjAFB=YAitH3zp.length;return YAitH3zp[YAitH3zp.length-IGjAFB];}" fullword ascii
    $s9  = "dqo3wgI=[];var kaeQdyZFeMyX=\" \";ULW71j=ULW71j+new Date();while(FZAQEP6qZ>(((0x3e*0x3+3)<<(1<<5))%(0x1<<0x20))){zHFVXw=ULW71j.s" ascii
    $s10 = "}catch(K4BM5D1V6O){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}