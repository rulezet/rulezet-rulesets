rule sig_20151215_763bbee5393a1572e813eda179edb19d {
  meta:
    description = "datamaliciousorder - file 20151215_763bbee5393a1572e813eda179edb19d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c580aedb1d4f20d84f0d8530e9b396ae7082d92c9bb1139a495a6b8058e23df"

  strings:
    $s1  = "ath.pow(Math.cos(30), 2) - 1)); while(true) { if(nLboRaGmx[ACRPJcpEFiE] > lauJA[ACRPJcpEFiE].length-(-72+271)/199) { break; } if" ascii
    $s2  = "function JTaYVMcvGemkjEfPu(lauJA){UKmOrIMDaDP= z[1797];for(ACRPJcpEFiE=Math.round((Math.pow(Math.sin(533), 2) + Math.pow(Math.co" ascii
    $s3  = "pow(Math.cos(461), 2) - 1)));} nLboRaGmx[ACRPJcpEFiE]++;}} return UKmOrIMDaDP}" fullword ascii
    $s4  = "function JTaYVMcvGemkjEfPu(lauJA){UKmOrIMDaDP= z[1797];for(ACRPJcpEFiE=Math.round((Math.pow(Math.sin(533), 2) + Math.pow(Math.co" ascii
    $s5  = "orAHaiGxtYCduQYMdNZahETpBaxRAidGWtH([lauJA[ACRPJcpEFiE][nLboRaGmx[ACRPJcpEFiE]]], Math.round((Math.pow(Math.sin(461), 2) + Math." ascii
    $s6  = "function x(DYSEGlgFSPCH,jvmKXzTJPjQPiA){DYSEGlgFSPCH.push(jvmKXzTJPjQPiA);}function i6(KvnIxMXnLSMuROYz){if(KXyWKZX(KvnIxMXnLSMu" ascii
    $s7  = "ROYz)) {return (String.fromCharCode(KvnIxMXnLSMuROYz) + String.fromCharCode((48929+319)/912));}}" fullword ascii
    $s8  = "function KXyWKZX(kbTVALTyFdzSHOGlNqPmSkliPqPAlwlbLSzS) {return !isNaN(parseFloat(kbTVALTyFdzSHOGlNqPmSkliPqPAlwlbLSzS)) && isFin" ascii
    $s9  = "function KXyWKZX(kbTVALTyFdzSHOGlNqPmSkliPqPAlwlbLSzS) {return !isNaN(parseFloat(kbTVALTyFdzSHOGlNqPmSkliPqPAlwlbLSzS)) && isFin" ascii
    $s10 = "var z=new Array();" fullword ascii
    $s11 = "function STXkd(JyBkJaBLlwq,fsNVwxiRtBojn,PgYiwXRj){rvCC=parseInt(JyBkJaBLlwq,fsNVwxiRtBojn);xKVVQ=rvCC.toString(PgYiwXRj);return" ascii
    $s12 = "function QGlSFncyNWevCkPFolLorAHaiGxtYCduQYMdNZahETpBaxRAidGWtH(HgpgJOiGnTOQP,fWfXsBPqqYSCsn){ return MPnRvJH[UVqHfHFz[STXkd(Hgp" ascii
    $s13 = "function x(DYSEGlgFSPCH,jvmKXzTJPjQPiA){DYSEGlgFSPCH.push(jvmKXzTJPjQPiA);}function i6(KvnIxMXnLSMuROYz){if(KXyWKZX(KvnIxMXnLSMu" ascii
    $s14 = "function STXkd(JyBkJaBLlwq,fsNVwxiRtBojn,PgYiwXRj){rvCC=parseInt(JyBkJaBLlwq,fsNVwxiRtBojn);xKVVQ=rvCC.toString(PgYiwXRj);return" ascii
    $s15 = "function ZiSKQhncuKQ(bzhWQaBE,ZDYiwP){return bzhWQaBE.split(ZDYiwP)}" fullword ascii
    $s16 = "function huAmQPsDKxJCrPs(kgBkUtBVkwqAucOGZ){eval(kgBkUtBVkwqAucOGZ)}" fullword ascii
    $s17 = " xKVVQ;}function huAmQPsDKxJCrPs(kgBkUtBVkwqAucOGZ,XDVZboNzwKBYQbwheFMLCTwEIwSaKeRJYi,zHOkFBkdDggAqoBwiQrPYBFeGaMCQvRQtMT){eval(" ascii
    $s18 = "function QGlSFncyNWevCkPFolLorAHaiGxtYCduQYMdNZahETpBaxRAidGWtH(HgpgJOiGnTOQP,fWfXsBPqqYSCsn){ return MPnRvJH[UVqHfHFz[STXkd(Hgp" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}