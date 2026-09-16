rule TTP_XOR_MULT_DOSStub_f13e {
  strings:
    $key_f13e = { a5 56 [2] d1 4e [2] 96 4c [2] d1 5d [2] 9f 51 [2] 93 5b [2] 84 50 [2] 9f 1e [2] a2 }

  condition:
    any of them
}