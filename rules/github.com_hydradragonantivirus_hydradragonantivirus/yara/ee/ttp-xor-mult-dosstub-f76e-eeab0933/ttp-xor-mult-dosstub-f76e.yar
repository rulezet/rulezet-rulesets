rule TTP_XOR_MULT_DOSStub_f76e {
  strings:
    $key_f76e = { a3 06 [2] d7 1e [2] 90 1c [2] d7 0d [2] 99 01 [2] 95 0b [2] 82 00 [2] 99 4e [2] a4 }

  condition:
    any of them
}