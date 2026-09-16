rule TTP_XOR_MULT_DOSStub_f1b2 {
  strings:
    $key_f1b2 = { a5 da [2] d1 c2 [2] 96 c0 [2] d1 d1 [2] 9f dd [2] 93 d7 [2] 84 dc [2] 9f 92 [2] a2 }

  condition:
    any of them
}