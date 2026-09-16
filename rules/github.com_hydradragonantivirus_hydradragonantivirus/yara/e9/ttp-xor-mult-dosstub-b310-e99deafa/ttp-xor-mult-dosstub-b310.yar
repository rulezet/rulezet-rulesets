rule TTP_XOR_MULT_DOSStub_b310 {
  strings:
    $key_b310 = { e7 78 [2] 93 60 [2] d4 62 [2] 93 73 [2] dd 7f [2] d1 75 [2] c6 7e [2] dd 30 [2] e0 }

  condition:
    any of them
}