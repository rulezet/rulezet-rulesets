rule TTP_XOR_MULT_DOSStub_f72e {
  strings:
    $key_f72e = { a3 46 [2] d7 5e [2] 90 5c [2] d7 4d [2] 99 41 [2] 95 4b [2] 82 40 [2] 99 0e [2] a4 }

  condition:
    any of them
}