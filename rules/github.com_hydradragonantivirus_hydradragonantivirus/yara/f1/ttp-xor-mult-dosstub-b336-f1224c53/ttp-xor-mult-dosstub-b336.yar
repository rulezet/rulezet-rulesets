rule TTP_XOR_MULT_DOSStub_b336 {
  strings:
    $key_b336 = { e7 5e [2] 93 46 [2] d4 44 [2] 93 55 [2] dd 59 [2] d1 53 [2] c6 58 [2] dd 16 [2] e0 }

  condition:
    any of them
}