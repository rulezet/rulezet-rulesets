rule TTP_XOR_MULT_DOSStub_550e {
  strings:
    $key_550e = { 01 66 [2] 75 7e [2] 32 7c [2] 75 6d [2] 3b 61 [2] 37 6b [2] 20 60 [2] 3b 2e [2] 06 }

  condition:
    any of them
}