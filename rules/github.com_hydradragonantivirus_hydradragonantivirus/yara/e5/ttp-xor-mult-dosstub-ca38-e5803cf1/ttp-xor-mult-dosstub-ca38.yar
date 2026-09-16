rule TTP_XOR_MULT_DOSStub_ca38 {
  strings:
    $key_ca38 = { 9e 50 [2] ea 48 [2] ad 4a [2] ea 5b [2] a4 57 [2] a8 5d [2] bf 56 [2] a4 18 [2] 99 }

  condition:
    any of them
}