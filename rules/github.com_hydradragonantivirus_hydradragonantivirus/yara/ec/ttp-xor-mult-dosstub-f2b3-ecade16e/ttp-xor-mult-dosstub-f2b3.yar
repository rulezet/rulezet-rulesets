rule TTP_XOR_MULT_DOSStub_f2b3 {
  strings:
    $key_f2b3 = { a6 db [2] d2 c3 [2] 95 c1 [2] d2 d0 [2] 9c dc [2] 90 d6 [2] 87 dd [2] 9c 93 [2] a1 }

  condition:
    any of them
}