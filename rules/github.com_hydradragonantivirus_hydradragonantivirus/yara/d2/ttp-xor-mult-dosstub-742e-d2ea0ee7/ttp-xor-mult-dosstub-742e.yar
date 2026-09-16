rule TTP_XOR_MULT_DOSStub_742e {
  strings:
    $key_742e = { 20 46 [2] 54 5e [2] 13 5c [2] 54 4d [2] 1a 41 [2] 16 4b [2] 01 40 [2] 1a 0e [2] 27 }

  condition:
    any of them
}