rule TTP_XOR_MULT_DOSStub_f17e {
  strings:
    $key_f17e = { a5 16 [2] d1 0e [2] 96 0c [2] d1 1d [2] 9f 11 [2] 93 1b [2] 84 10 [2] 9f 5e [2] a2 }

  condition:
    any of them
}