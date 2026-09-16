rule TTP_XOR_MULT_DOSStub_705e {
  strings:
    $key_705e = { 24 36 [2] 50 2e [2] 17 2c [2] 50 3d [2] 1e 31 [2] 12 3b [2] 05 30 [2] 1e 7e [2] 23 }

  condition:
    any of them
}