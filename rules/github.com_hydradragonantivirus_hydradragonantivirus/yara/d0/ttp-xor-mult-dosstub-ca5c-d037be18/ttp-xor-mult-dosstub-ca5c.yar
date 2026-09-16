rule TTP_XOR_MULT_DOSStub_ca5c {
  strings:
    $key_ca5c = { 9e 34 [2] ea 2c [2] ad 2e [2] ea 3f [2] a4 33 [2] a8 39 [2] bf 32 [2] a4 7c [2] 99 }

  condition:
    any of them
}