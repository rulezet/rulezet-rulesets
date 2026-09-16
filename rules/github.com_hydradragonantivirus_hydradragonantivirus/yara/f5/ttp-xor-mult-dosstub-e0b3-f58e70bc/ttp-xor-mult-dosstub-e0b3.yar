rule TTP_XOR_MULT_DOSStub_e0b3 {
  strings:
    $key_e0b3 = { b4 db [2] c0 c3 [2] 87 c1 [2] c0 d0 [2] 8e dc [2] 82 d6 [2] 95 dd [2] 8e 93 [2] b3 }

  condition:
    any of them
}