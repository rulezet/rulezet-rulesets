rule TTP_XOR_MULT_DOSStub_743e {
  strings:
    $key_743e = { 20 56 [2] 54 4e [2] 13 4c [2] 54 5d [2] 1a 51 [2] 16 5b [2] 01 50 [2] 1a 1e [2] 27 }

  condition:
    any of them
}