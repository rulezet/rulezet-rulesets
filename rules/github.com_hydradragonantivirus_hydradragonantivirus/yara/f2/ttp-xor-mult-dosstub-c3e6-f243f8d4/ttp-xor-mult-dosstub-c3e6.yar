rule TTP_XOR_MULT_DOSStub_c3e6 {
  strings:
    $key_c3e6 = { 97 8e [2] e3 96 [2] a4 94 [2] e3 85 [2] ad 89 [2] a1 83 [2] b6 88 [2] ad c6 [2] 90 }

  condition:
    any of them
}