rule TTP_XOR_MULT_DOSStub_556e {
  strings:
    $key_556e = { 01 06 [2] 75 1e [2] 32 1c [2] 75 0d [2] 3b 01 [2] 37 0b [2] 20 00 [2] 3b 4e [2] 06 }

  condition:
    any of them
}