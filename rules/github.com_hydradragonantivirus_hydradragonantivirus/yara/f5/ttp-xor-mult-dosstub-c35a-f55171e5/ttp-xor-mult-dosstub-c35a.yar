rule TTP_XOR_MULT_DOSStub_c35a {
  strings:
    $key_c35a = { 97 32 [2] e3 2a [2] a4 28 [2] e3 39 [2] ad 35 [2] a1 3f [2] b6 34 [2] ad 7a [2] 90 }

  condition:
    any of them
}