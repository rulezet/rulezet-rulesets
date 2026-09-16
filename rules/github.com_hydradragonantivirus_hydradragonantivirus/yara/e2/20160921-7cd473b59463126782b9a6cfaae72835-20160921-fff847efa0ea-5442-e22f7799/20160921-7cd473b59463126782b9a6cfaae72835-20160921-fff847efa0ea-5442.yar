rule _20160921_7cd473b59463126782b9a6cfaae72835_20160921_fff847efa0ea_5442 {
  meta:
    description = "datamaliciousorder - from files 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash2       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1 = "000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx" ascii
    $s2 = "function f000(){return \"KDh\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){re" ascii
    $s3 = ",(function f000(){return \"HJm\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s4 = "on f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"" ascii
    $s5 = "000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}