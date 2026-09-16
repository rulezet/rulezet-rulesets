rule TTP_XOR_MULT_DOSStub_377e {
  strings:
    $key_377e = { 63 16 [2] 17 0e [2] 50 0c [2] 17 1d [2] 59 11 [2] 55 1b [2] 42 10 [2] 59 5e [2] 64 }

  condition:
    any of them
}