rule TTP_XOR_MULT_DOSStub_397e {
  strings:
    $key_397e = { 6d 16 [2] 19 0e [2] 5e 0c [2] 19 1d [2] 57 11 [2] 5b 1b [2] 4c 10 [2] 57 5e [2] 6a }

  condition:
    any of them
}