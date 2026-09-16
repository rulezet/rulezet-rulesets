rule TTP_XOR_MULT_DOSStub_24b2 {
  strings:
    $key_24b2 = { 70 da [2] 04 c2 [2] 43 c0 [2] 04 d1 [2] 4a dd [2] 46 d7 [2] 51 dc [2] 4a 92 [2] 77 }

  condition:
    any of them
}