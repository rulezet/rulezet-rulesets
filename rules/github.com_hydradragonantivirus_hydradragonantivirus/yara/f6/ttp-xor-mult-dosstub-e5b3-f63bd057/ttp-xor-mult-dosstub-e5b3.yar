rule TTP_XOR_MULT_DOSStub_e5b3 {
  strings:
    $key_e5b3 = { b1 db [2] c5 c3 [2] 82 c1 [2] c5 d0 [2] 8b dc [2] 87 d6 [2] 90 dd [2] 8b 93 [2] b6 }

  condition:
    any of them
}