rule TTP_XOR_MULT_DOSStub_714e {
  strings:
    $key_714e = { 25 26 [2] 51 3e [2] 16 3c [2] 51 2d [2] 1f 21 [2] 13 2b [2] 04 20 [2] 1f 6e [2] 22 }

  condition:
    any of them
}