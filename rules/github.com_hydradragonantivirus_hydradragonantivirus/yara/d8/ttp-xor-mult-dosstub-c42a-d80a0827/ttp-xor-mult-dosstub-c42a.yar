rule TTP_XOR_MULT_DOSStub_c42a {
  strings:
    $key_c42a = { 90 42 [2] e4 5a [2] a3 58 [2] e4 49 [2] aa 45 [2] a6 4f [2] b1 44 [2] aa 0a [2] 97 }

  condition:
    any of them
}