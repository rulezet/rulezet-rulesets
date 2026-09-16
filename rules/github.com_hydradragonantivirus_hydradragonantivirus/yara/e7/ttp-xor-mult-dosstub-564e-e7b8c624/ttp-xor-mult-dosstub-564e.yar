rule TTP_XOR_MULT_DOSStub_564e {
  strings:
    $key_564e = { 02 26 [2] 76 3e [2] 31 3c [2] 76 2d [2] 38 21 [2] 34 2b [2] 23 20 [2] 38 6e [2] 05 }

  condition:
    any of them
}