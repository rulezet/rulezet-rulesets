rule sig_20151215_1b8a99bdc96031a7f2d62f2b7832d9e9 {
  meta:
    description = "datamaliciousorder - file 20151215_1b8a99bdc96031a7f2d62f2b7832d9e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06a3059a2cfbdf9c283c1d90444b6d9c4c044958e692d470ad0c554a664a9add"

  strings:
    $s1  = "(Math.cos(160), 2) - 1)));} kMziRnmMK[sVLbzXwdXwu]++;}} return fiTIhGBIJhr}" fullword ascii
    $s2  = "function neODushIJYtzHoEZD(GDdDE){fiTIhGBIJhr= p[1766];for(sVLbzXwdXwu=Math.round((Math.pow(Math.sin(159), 2) + Math.pow(Math.co" ascii
    $s3  = "h.pow(Math.cos(2), 2) - 1)); while(true) { if(kMziRnmMK[sVLbzXwdXwu] > GDdDE[sVLbzXwdXwu].length-(572+272)/844) { break; } if (z" ascii
    $s4  = "function neODushIJYtzHoEZD(GDdDE){fiTIhGBIJhr= p[1766];for(sVLbzXwdXwu=Math.round((Math.pow(Math.sin(159), 2) + Math.pow(Math.co" ascii
    $s5  = "QnOC)) {return (String.fromCharCode(rdEKpTJhnmelQnOC) + String.fromCharCode((35296+329)/475));}}" fullword ascii
    $s6  = "function G(EBnSPWdFvDYF,zcHFWBtqvaHAmG){EBnSPWdFvDYF.push(zcHFWBtqvaHAmG);}function P2(rdEKpTJhnmelQnOC){if(zdaNyAI(rdEKpTJhnmel" ascii
    $s7  = "function zdaNyAI(JcSKXgSVjWrMuAqSovZsBsHmsEwtUHnURjTU) {return !isNaN(parseFloat(JcSKXgSVjWrMuAqSovZsBsHmsEwtUHnURjTU)) && isFin" ascii
    $s8  = "function zdaNyAI(JcSKXgSVjWrMuAqSovZsBsHmsEwtUHnURjTU) {return !isNaN(parseFloat(JcSKXgSVjWrMuAqSovZsBsHmsEwtUHnURjTU)) && isFin" ascii
    $s9  = "var p=new Array();" fullword ascii
    $s10 = "function kphxN(AKhVwauONrJ,MkcBwhJdagpvS,JOfRfgBt){vEHp=parseInt(AKhVwauONrJ,MkcBwhJdagpvS);tuUcd=vEHp.toString(JOfRfgBt);return" ascii
    $s11 = "function CGgkvQGQyYh(CUFdNkUb,eJFKhv){return CUFdNkUb.split(eJFKhv)}" fullword ascii
    $s12 = "function WCDKdQgJsRBGFSs(eeDUiuAKjbmGMptMB){eval(eeDUiuAKjbmGMptMB)}" fullword ascii
    $s13 = "function wjjwdYjVbBTtQxXLKHCWjwisLJyhyeMjsKpRQNcWOKKssORXGyPTNp(bftZrBMwBfKYL,foJRKfCcYLPmRS){ return WceEfYP[GTpTeGtv[kphxN(bft" ascii
    $s14 = "function wjjwdYjVbBTtQxXLKHCWjwisLJyhyeMjsKpRQNcWOKKssORXGyPTNp(bftZrBMwBfKYL,foJRKfCcYLPmRS){ return WceEfYP[GTpTeGtv[kphxN(bft" ascii
    $s15 = "function kphxN(AKhVwauONrJ,MkcBwhJdagpvS,JOfRfgBt){vEHp=parseInt(AKhVwauONrJ,MkcBwhJdagpvS);tuUcd=vEHp.toString(JOfRfgBt);return" ascii
    $s16 = "function G(EBnSPWdFvDYF,zcHFWBtqvaHAmG){EBnSPWdFvDYF.push(zcHFWBtqvaHAmG);}function P2(rdEKpTJhnmelQnOC){if(zdaNyAI(rdEKpTJhnmel" ascii
    $s17 = " tuUcd;}function WCDKdQgJsRBGFSs(eeDUiuAKjbmGMptMB,dGsOzUETkjQVJyhaXnVOjEdvqWmrkKMXAj,RpdCmxpRoNhcojXcOqqzEwNOsBucjktwcrs){eval(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}