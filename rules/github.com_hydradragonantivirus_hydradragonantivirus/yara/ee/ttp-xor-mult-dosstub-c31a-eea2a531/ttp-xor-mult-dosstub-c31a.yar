rule TTP_XOR_MULT_DOSStub_c31a {
  strings:
    $key_c31a = { 97 72 [2] e3 6a [2] a4 68 [2] e3 79 [2] ad 75 [2] a1 7f [2] b6 74 [2] ad 3a [2] 90 }

  condition:
    any of them
}