rule TTP_XOR_MULT_DOSStub_c310 {
  strings:
    $key_c310 = { 97 78 [2] e3 60 [2] a4 62 [2] e3 73 [2] ad 7f [2] a1 75 [2] b6 7e [2] ad 30 [2] 90 }

  condition:
    any of them
}