rule TTP_XOR_MULT_DOSStub_f4b3 {
  strings:
    $key_f4b3 = { a0 db [2] d4 c3 [2] 93 c1 [2] d4 d0 [2] 9a dc [2] 96 d6 [2] 81 dd [2] 9a 93 [2] a7 }

  condition:
    any of them
}