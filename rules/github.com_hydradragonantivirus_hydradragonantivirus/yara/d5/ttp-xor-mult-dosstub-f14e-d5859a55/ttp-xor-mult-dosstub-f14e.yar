rule TTP_XOR_MULT_DOSStub_f14e {
  strings:
    $key_f14e = { a5 26 [2] d1 3e [2] 96 3c [2] d1 2d [2] 9f 21 [2] 93 2b [2] 84 20 [2] 9f 6e [2] a2 }

  condition:
    any of them
}