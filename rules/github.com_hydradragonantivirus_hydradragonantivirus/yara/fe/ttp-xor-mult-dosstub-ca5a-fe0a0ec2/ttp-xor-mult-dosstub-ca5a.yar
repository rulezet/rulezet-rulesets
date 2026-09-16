rule TTP_XOR_MULT_DOSStub_ca5a {
  strings:
    $key_ca5a = { 9e 32 [2] ea 2a [2] ad 28 [2] ea 39 [2] a4 35 [2] a8 3f [2] bf 34 [2] a4 7a [2] 99 }

  condition:
    any of them
}