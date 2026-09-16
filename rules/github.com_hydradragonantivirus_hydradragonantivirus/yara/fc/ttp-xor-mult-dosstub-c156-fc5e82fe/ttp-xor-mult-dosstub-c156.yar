rule TTP_XOR_MULT_DOSStub_c156 {
  strings:
    $key_c156 = { 95 3e [2] e1 26 [2] a6 24 [2] e1 35 [2] af 39 [2] a3 33 [2] b4 38 [2] af 76 [2] 92 }

  condition:
    any of them
}