rule TTP_XOR_MULT_DOSStub_b337 {
  strings:
    $key_b337 = { e7 5f [2] 93 47 [2] d4 45 [2] 93 54 [2] dd 58 [2] d1 52 [2] c6 59 [2] dd 17 [2] e0 }

  condition:
    any of them
}