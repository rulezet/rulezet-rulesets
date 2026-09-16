rule TTP_XOR_MULT_DOSStub_c331 {
  strings:
    $key_c331 = { 97 59 [2] e3 41 [2] a4 43 [2] e3 52 [2] ad 5e [2] a1 54 [2] b6 5f [2] ad 11 [2] 90 }

  condition:
    any of them
}