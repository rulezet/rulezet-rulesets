rule sig_20151211_77b5a3e6110a88d063748c62baa32137 {
  meta:
    description = "datamaliciousorder - file 20151211_77b5a3e6110a88d063748c62baa32137.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1951813a38376a11919bf893e30a9ba3cd5b71bb5397247022386bfd35a4a0e"

  strings:
    $s1  = "function jKnPdwP(GRVYwuLxWgUMlMCXfoffzufyffYDRSBDJvTS) {return !isNaN(parseFloat(GRVYwuLxWgUMlMCXfoffzufyffYDRSBDJvTS)) && isFin" ascii
    $s2  = "function jKnPdwP(GRVYwuLxWgUMlMCXfoffzufyffYDRSBDJvTS) {return !isNaN(parseFloat(GRVYwuLxWgUMlMCXfoffzufyffYDRSBDJvTS)) && isFin" ascii
    $s3  = "function xCYlZMGvuTOoJYImFamuYpThdWCDcyHAVMwxAnbnWhhtNbcgWQOjLP(TjdnzIXZDMLum,DkNTKkTdFlJyeU){ return PScsL[ygrPA(TjdnzIXZDMLum[" ascii
    $s4  = " NIvDo;}function ovpCgVHFfRnaCGl(acgIgvTzNOSBQkAmx){eval(acgIgvTzNOSBQkAmx)}" fullword ascii
    $s5  = ";RdoQzsOQj[PQPjSaPQQLH]=(-787+787)/291; while(true) { if(RdoQzsOQj[PQPjSaPQQLH] > sRPFP[PQPjSaPQQLH].length-(-9+276)/267) { brea" ascii
    $s6  = "var b=new Array(\"2e\",\"28\",\"26\",\"2a\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s7  = "var K=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5a\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s8  = "function cyukuDHmQQKICFSqd(sRPFP){LfZHwexrODA= '';PQPjSaPQQLH=(-999+999)/861; while(true){if(PQPjSaPQQLH >= (1044+550)/797)break" ascii
    $s9  = "function edkqWLiBbxz(OAOzkPAg,qYFEVu){return OAOzkPAg.split(qYFEVu)}" fullword ascii
    $s10 = "function ygrPA(cSQRBTqygVF,AvwhqbqTzUrfs,RxeavuaH){dpfp=parseInt(cSQRBTqygVF,AvwhqbqTzUrfs);NIvDo=dpfp.toString(RxeavuaH);return" ascii
    $s11 = "function ygrPA(cSQRBTqygVF,AvwhqbqTzUrfs,RxeavuaH){dpfp=parseInt(cSQRBTqygVF,AvwhqbqTzUrfs);NIvDo=dpfp.toString(RxeavuaH);return" ascii
    $s12 = "var b=new Array(\"2e\",\"28\",\"26\",\"2a\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s13 = "function xCYlZMGvuTOoJYImFamuYpThdWCDcyHAVMwxAnbnWhhtNbcgWQOjLP(TjdnzIXZDMLum,DkNTKkTdFlJyeU){ return PScsL[ygrPA(TjdnzIXZDMLum[" ascii
    $s14 = "function cyukuDHmQQKICFSqd(sRPFP){LfZHwexrODA= '';PQPjSaPQQLH=(-999+999)/861; while(true){if(PQPjSaPQQLH >= (1044+550)/797)break" ascii
    $s15 = "var K=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5a\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s16 = "+;}PQPjSaPQQLH++;} return LfZHwexrODA}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}