rule TTP_XOR_MULT_DOSStub_ca07 {
  strings:
    $key_ca07 = { 9e 6f [2] ea 77 [2] ad 75 [2] ea 64 [2] a4 68 [2] a8 62 [2] bf 69 [2] a4 27 [2] 99 }

  condition:
    any of them
}