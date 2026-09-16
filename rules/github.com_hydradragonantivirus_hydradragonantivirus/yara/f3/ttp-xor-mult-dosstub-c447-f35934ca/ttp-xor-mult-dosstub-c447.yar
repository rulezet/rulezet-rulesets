rule TTP_XOR_MULT_DOSStub_c447 {
  strings:
    $key_c447 = { 90 2f [2] e4 37 [2] a3 35 [2] e4 24 [2] aa 28 [2] a6 22 [2] b1 29 [2] aa 67 [2] 97 }

  condition:
    any of them
}