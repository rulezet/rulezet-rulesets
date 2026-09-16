rule TTP_XOR_MULT_DOSStub_18c8 {
  strings:
    $key_18c8 = { 4c a0 [2] 38 b8 [2] 7f ba [2] 38 ab [2] 76 a7 [2] 7a ad [2] 6d a6 [2] 76 e8 [2] 4b }

  condition:
    any of them
}