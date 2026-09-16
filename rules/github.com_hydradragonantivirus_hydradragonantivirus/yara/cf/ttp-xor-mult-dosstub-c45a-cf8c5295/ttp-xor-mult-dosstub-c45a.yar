rule TTP_XOR_MULT_DOSStub_c45a {
  strings:
    $key_c45a = { 90 32 [2] e4 2a [2] a3 28 [2] e4 39 [2] aa 35 [2] a6 3f [2] b1 34 [2] aa 7a [2] 97 }

  condition:
    any of them
}