rule TTP_XOR_MULT_DOSStub_c4b3 {
  strings:
    $key_c4b3 = { 90 db [2] e4 c3 [2] a3 c1 [2] e4 d0 [2] aa dc [2] a6 d6 [2] b1 dd [2] aa 93 [2] 97 }

  condition:
    any of them
}