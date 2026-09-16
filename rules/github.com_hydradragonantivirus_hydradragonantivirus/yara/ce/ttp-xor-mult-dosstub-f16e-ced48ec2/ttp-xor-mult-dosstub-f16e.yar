rule TTP_XOR_MULT_DOSStub_f16e {
  strings:
    $key_f16e = { a5 06 [2] d1 1e [2] 96 1c [2] d1 0d [2] 9f 01 [2] 93 0b [2] 84 00 [2] 9f 4e [2] a2 }

  condition:
    any of them
}