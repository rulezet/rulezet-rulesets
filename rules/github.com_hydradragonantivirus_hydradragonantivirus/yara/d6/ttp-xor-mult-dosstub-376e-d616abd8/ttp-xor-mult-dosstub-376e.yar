rule TTP_XOR_MULT_DOSStub_376e {
  strings:
    $key_376e = { 63 06 [2] 17 1e [2] 50 1c [2] 17 0d [2] 59 01 [2] 55 0b [2] 42 00 [2] 59 4e [2] 64 }

  condition:
    any of them
}