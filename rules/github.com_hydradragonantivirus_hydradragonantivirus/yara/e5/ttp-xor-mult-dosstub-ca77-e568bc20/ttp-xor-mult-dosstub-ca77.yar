rule TTP_XOR_MULT_DOSStub_ca77 {
  strings:
    $key_ca77 = { 9e 1f [2] ea 07 [2] ad 05 [2] ea 14 [2] a4 18 [2] a8 12 [2] bf 19 [2] a4 57 [2] 99 }

  condition:
    any of them
}