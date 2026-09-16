rule TTP_XOR_MULT_DOSStub_b7a8 {
  strings:
    $key_b7a8 = { e3 c0 [2] 97 d8 [2] d0 da [2] 97 cb [2] d9 c7 [2] d5 cd [2] c2 c6 [2] d9 88 [2] e4 }

  condition:
    any of them
}