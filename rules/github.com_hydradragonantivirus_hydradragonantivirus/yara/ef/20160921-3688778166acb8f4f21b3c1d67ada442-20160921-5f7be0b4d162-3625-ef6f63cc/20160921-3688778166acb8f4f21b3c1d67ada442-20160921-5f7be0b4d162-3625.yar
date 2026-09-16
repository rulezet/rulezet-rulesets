rule _20160921_3688778166acb8f4f21b3c1d67ada442_20160921_5f7be0b4d162_3625 {
  meta:
    description = "datamaliciousorder - from files 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash2       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash3       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"

  strings:
    $s1 = "(function fuck(){return \"Cd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){re" ascii
    $s2 = "urn \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(" ascii
    $s3 = " fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"" ascii
    $s4 = "urn \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii
    $s5 = ")(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck" ascii
    $s6 = "on fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}