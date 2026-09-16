rule TTP_XOR_MULT_DOSStub_c445 {
  strings:
    $key_c445 = { 90 2d [2] e4 35 [2] a3 37 [2] e4 26 [2] aa 2a [2] a6 20 [2] b1 2b [2] aa 65 [2] 97 }

  condition:
    any of them
}