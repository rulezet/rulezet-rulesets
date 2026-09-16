rule sig_20160525_ef6032e2c50a5b859a3cc0244191db6f {
  meta:
    description = "datamaliciousorder - file 20160525_ef6032e2c50a5b859a3cc0244191db6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b164574f299c79b87895ec32ed84819f7278267d62634e4b0ad3e00eede48257"

  strings:
    $s1  = "function arKaea(LcetUhqjQGKaS) {var NEfGwC = CpnzqopTurGOYTnYpNbml.join(LyHCpdjMKlpuRjbqbWwE[0]);var qXyxK, nGplOgpDbAXeNigoUpZg" ascii
    $s2  = "Math.pow(Math.cos(854), 2) - 1))-244) | mCucLXHlTADvhFECXGI;qXyxK = fUWGj>> (302 + Math.round((Math.pow(Math.sin(959), 2) + Math" ascii
    $s3  = "(Math.pow(Math.sin(461), 2) + Math.pow(Math.cos(461), 2) - 1))-76)) qycPgMBPRBpvGpvSDJJyN += Rf(qXyxK);else if (mCucLXHlTADvhFEC" ascii
    $s4  = "function mPfNC(OVTbumYpjAFxCWnKqmBUodxq,dKhvMqJ){return OVTbumYpjAFxCWnKqmBUodxq.charAt(dKhvMqJ);}" fullword ascii
    $s5  = "function arKaea(LcetUhqjQGKaS) {var NEfGwC = CpnzqopTurGOYTnYpNbml.join(LyHCpdjMKlpuRjbqbWwE[0]);var qXyxK, nGplOgpDbAXeNigoUpZg" ascii
    $s6  = "gCPZDZIBEazPi(qXyxK, nGplOgpDbAXeNigoUpZgWh);else qycPgMBPRBpvGpvSDJJyN += SCyFbsSemgKCrCJgon(qXyxK, nGplOgpDbAXeNigoUpZgWh, nEm" ascii
    $s7  = "function nViEXuESgCPZDZIBEazPi(aAUsyjvdGMwUHX,PGyzNMXBePxnltFtVz){return String.fromCharCode(aAUsyjvdGMwUHX,PGyzNMXBePxnltFtVz);" ascii
    $s8  = "function hqoKvGzaSOwzg(luwATGc,HKwVlAAqSWmeiLUx){return luwATGc.indexOf(HKwVlAAqSWmeiLUx);}" fullword ascii
    $s9  = "function Rf(keIWOk){return String.fromCharCode(keIWOk);}" fullword ascii
    $s10 = "yLNCdfJYrHiedKwpbuBi);} while (qZjobIAdqSGybMt < LcetUhqjQGKaS.length);return qycPgMBPRBpvGpvSDJJyN;}" fullword ascii
    $s11 = "function nViEXuESgCPZDZIBEazPi(aAUsyjvdGMwUHX,PGyzNMXBePxnltFtVz){return String.fromCharCode(aAUsyjvdGMwUHX,PGyzNMXBePxnltFtVz);" ascii
    $s12 = "function SCyFbsSemgKCrCJgon(XhvlvG,pItZGcVX,fZViYFbhCEwYBo){return String.fromCharCode(XhvlvG,pItZGcVX,fZViYFbhCEwYBo);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}