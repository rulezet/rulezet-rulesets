rule TTP_XOR_MULT_DOSStub_c450 {
  strings:
    $key_c450 = { 90 38 [2] e4 20 [2] a3 22 [2] e4 33 [2] aa 3f [2] a6 35 [2] b1 3e [2] aa 70 [2] 97 }

  condition:
    any of them
}