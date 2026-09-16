rule TTP_XOR_MULT_DOSStub_02b2 {
  strings:
    $key_02b2 = { 56 da [2] 22 c2 [2] 65 c0 [2] 22 d1 [2] 6c dd [2] 60 d7 [2] 77 dc [2] 6c 92 [2] 51 }

  condition:
    any of them
}