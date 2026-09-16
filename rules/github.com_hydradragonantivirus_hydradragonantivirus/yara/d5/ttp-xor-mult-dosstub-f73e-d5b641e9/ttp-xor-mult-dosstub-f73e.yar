rule TTP_XOR_MULT_DOSStub_f73e {
  strings:
    $key_f73e = { a3 56 [2] d7 4e [2] 90 4c [2] d7 5d [2] 99 51 [2] 95 5b [2] 82 50 [2] 99 1e [2] a4 }

  condition:
    any of them
}