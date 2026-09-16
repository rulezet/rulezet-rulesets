rule TTP_XOR_MULT_DOSStub_706e {
  strings:
    $key_706e = { 24 06 [2] 50 1e [2] 17 1c [2] 50 0d [2] 1e 01 [2] 12 0b [2] 05 00 [2] 1e 4e [2] 23 }

  condition:
    any of them
}