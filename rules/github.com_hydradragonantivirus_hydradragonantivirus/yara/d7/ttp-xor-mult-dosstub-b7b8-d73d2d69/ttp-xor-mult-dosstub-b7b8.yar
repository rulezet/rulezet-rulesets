rule TTP_XOR_MULT_DOSStub_b7b8 {
  strings:
    $key_b7b8 = { e3 d0 [2] 97 c8 [2] d0 ca [2] 97 db [2] d9 d7 [2] d5 dd [2] c2 d6 [2] d9 98 [2] e4 }

  condition:
    any of them
}