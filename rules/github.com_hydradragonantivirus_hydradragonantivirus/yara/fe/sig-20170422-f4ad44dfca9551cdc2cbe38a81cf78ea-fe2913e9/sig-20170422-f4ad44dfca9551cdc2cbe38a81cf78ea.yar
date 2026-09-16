rule sig_20170422_f4ad44dfca9551cdc2cbe38a81cf78ea {
  meta:
    description = "datamaliciousorder - file 20170422_f4ad44dfca9551cdc2cbe38a81cf78ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e43cc8ff0378165b41fbcd014e59eb7f36497711f942010613172af24045f6e"

  strings:
    $s1 = "function PjUwvsCeYubLpSQGdMh(LYIMQcqCvzoSastHK, PNxFWgOTBdQUlsMvChY) { " fullword ascii
    $s2 = "function rctopnqXhTHySxLFQi(BvUnjNKywCmSMqGsOJD) { return String.fromCharCode(BvUnjNKywCmSMqGsOJD); }" fullword ascii
    $s3 = "return LYIMQcqCvzoSastHK.split(PNxFWgOTBdQUlsMvChY).join(\"\"); }" fullword ascii
    $s4 = "if (PSvpYnuQkqEsXdoH.FolderExists(WtKqjBcUbiVTCuQIgk) == true) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}