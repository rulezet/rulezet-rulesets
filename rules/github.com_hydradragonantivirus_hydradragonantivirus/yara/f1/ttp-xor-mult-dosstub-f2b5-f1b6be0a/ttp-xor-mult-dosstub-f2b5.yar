rule TTP_XOR_MULT_DOSStub_f2b5 {
  strings:
    $key_f2b5 = { a6 dd [2] d2 c5 [2] 95 c7 [2] d2 d6 [2] 9c da [2] 90 d0 [2] 87 db [2] 9c 95 [2] a1 }

  condition:
    any of them
}