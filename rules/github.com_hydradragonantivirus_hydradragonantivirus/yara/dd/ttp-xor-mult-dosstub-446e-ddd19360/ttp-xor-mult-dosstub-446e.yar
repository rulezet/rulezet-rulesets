rule TTP_XOR_MULT_DOSStub_446e {
  strings:
    $key_446e = { 10 06 [2] 64 1e [2] 23 1c [2] 64 0d [2] 2a 01 [2] 26 0b [2] 31 00 [2] 2a 4e [2] 17 }

  condition:
    any of them
}