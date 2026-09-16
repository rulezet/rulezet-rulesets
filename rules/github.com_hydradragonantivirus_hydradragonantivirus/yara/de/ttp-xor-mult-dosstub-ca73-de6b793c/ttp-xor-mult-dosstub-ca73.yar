rule TTP_XOR_MULT_DOSStub_ca73 {
  strings:
    $key_ca73 = { 9e 1b [2] ea 03 [2] ad 01 [2] ea 10 [2] a4 1c [2] a8 16 [2] bf 1d [2] a4 53 [2] 99 }

  condition:
    any of them
}