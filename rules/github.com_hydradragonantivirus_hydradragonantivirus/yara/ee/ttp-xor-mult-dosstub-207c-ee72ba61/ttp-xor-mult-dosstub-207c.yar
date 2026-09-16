rule TTP_XOR_MULT_DOSStub_207c {
  strings:
    $key_207c = { 74 14 [2] 00 0c [2] 47 0e [2] 00 1f [2] 4e 13 [2] 42 19 [2] 55 12 [2] 4e 5c [2] 73 }

  condition:
    any of them
}