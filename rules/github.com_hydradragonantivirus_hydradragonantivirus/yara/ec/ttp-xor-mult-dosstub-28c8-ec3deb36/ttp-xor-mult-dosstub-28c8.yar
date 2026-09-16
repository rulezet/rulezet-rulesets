rule TTP_XOR_MULT_DOSStub_28c8 {
  strings:
    $key_28c8 = { 7c a0 [2] 08 b8 [2] 4f ba [2] 08 ab [2] 46 a7 [2] 4a ad [2] 5d a6 [2] 46 e8 [2] 7b }

  condition:
    any of them
}