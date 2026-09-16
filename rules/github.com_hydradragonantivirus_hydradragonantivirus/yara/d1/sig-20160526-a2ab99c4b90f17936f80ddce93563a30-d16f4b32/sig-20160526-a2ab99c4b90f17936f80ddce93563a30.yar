rule sig_20160526_a2ab99c4b90f17936f80ddce93563a30 {
  meta:
    description = "datamaliciousorder - file 20160526_a2ab99c4b90f17936f80ddce93563a30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ca14729dde02475b3e5dac8045822c5cd33bf21ea9c93724d6bb10484e05e68"

  strings:
    $s1  = "n(1), 2) + Math.pow(Math.cos(1), 2) - 1))-660)) JwbOzpLL += upYTHhZuuzokcS(rLrIxjEh, kVNeMWbRXBruApd);else JwbOzpLL += GoiFbcFjY" ascii
    $s2  = "function KvFqm(XxalirQXRZhnm) {var zJQoIFqJKyQYGvmaJbuW = hjdhW.join(dHanSyfupWWcsFuBjlNZGN[0]);var rLrIxjEh, kVNeMWbRXBruApd, W" ascii
    $s3  = "th.pow(Math.cos(606), 2) - 1))-458)) JwbOzpLL += Hl(rLrIxjEh);else if (aHaakvGNigcrgcSoBd == (724 + Math.round((Math.pow(Math.si" ascii
    $s4  = "function GGGBWMhDuiIJpCsNRzyySvUg(wBtINAC,sXHWLNXrWkPx){return wBtINAC.charAt(sXHWLNXrWkPx);}" fullword ascii
    $s5  = "function upYTHhZuuzokcS(eceVMRsaknPePhYDf,uVdRZLSXpNDGHcC){return String.fromCharCode(eceVMRsaknPePhYDf,uVdRZLSXpNDGHcC);}" fullword ascii
    $s6  = "function Bcwyx(LXUIlGiOn,JMyBnzcHSJjjTlz){return LXUIlGiOn.indexOf(JMyBnzcHSJjjTlz);}" fullword ascii
    $s7  = "io(rLrIxjEh, kVNeMWbRXBruApd, WKmRDwwPTTnaATybkP);} while (TmzPbikgerWPSYzGafihG < XxalirQXRZhnm.length);return JwbOzpLL;}" fullword ascii
    $s8  = "function Hl(bXBSPQDdtavlwqKz){return String.fromCharCode(bXBSPQDdtavlwqKz);}" fullword ascii
    $s9  = "function GoiFbcFjYio(ryGQdySopO,NJwlhqAFrtcYqWiIaBDkUDSj,leSFLVSeHIKLYiopkBzettIg){return String.fromCharCode(ryGQdySopO,NJwlhqA" ascii
    $s10 = "function GoiFbcFjYio(ryGQdySopO,NJwlhqAFrtcYqWiIaBDkUDSj,leSFLVSeHIKLYiopkBzettIg){return String.fromCharCode(ryGQdySopO,NJwlhqA" ascii
    $s11 = "function KvFqm(XxalirQXRZhnm) {var zJQoIFqJKyQYGvmaJbuW = hjdhW.join(dHanSyfupWWcsFuBjlNZGN[0]);var rLrIxjEh, kVNeMWbRXBruApd, W" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}