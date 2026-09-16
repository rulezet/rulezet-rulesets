rule TTP_XOR_MULT_DOSStub_546e {
  strings:
    $key_546e = { 00 06 [2] 74 1e [2] 33 1c [2] 74 0d [2] 3a 01 [2] 36 0b [2] 21 00 [2] 3a 4e [2] 07 }

  condition:
    any of them
}