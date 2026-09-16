rule TTP_XOR_MULT_DOSStub_e2b5 {
  strings:
    $key_e2b5 = { b6 dd [2] c2 c5 [2] 85 c7 [2] c2 d6 [2] 8c da [2] 80 d0 [2] 97 db [2] 8c 95 [2] b1 }

  condition:
    any of them
}