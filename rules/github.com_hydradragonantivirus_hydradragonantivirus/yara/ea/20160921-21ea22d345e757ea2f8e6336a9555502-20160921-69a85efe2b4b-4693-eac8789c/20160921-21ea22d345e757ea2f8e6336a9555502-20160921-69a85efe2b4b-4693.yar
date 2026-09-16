rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_69a85efe2b4b_4693 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_69a85efe2b4b34254269f0f82213bf2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"

  strings:
    $s1 = "\"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";})(),(fun" ascii
    $s2 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s3 = "Pu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(functi" ascii
    $s4 = "ck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s5 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}