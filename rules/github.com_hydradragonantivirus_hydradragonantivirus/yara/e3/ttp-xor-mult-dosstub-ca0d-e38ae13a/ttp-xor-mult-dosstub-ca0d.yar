rule TTP_XOR_MULT_DOSStub_ca0d {
  strings:
    $key_ca0d = { 9e 65 [2] ea 7d [2] ad 7f [2] ea 6e [2] a4 62 [2] a8 68 [2] bf 63 [2] a4 2d [2] 99 }

  condition:
    any of them
}