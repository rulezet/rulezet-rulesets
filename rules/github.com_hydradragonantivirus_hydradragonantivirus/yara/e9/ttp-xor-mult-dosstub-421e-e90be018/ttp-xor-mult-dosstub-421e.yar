rule TTP_XOR_MULT_DOSStub_421e {
  strings:
    $key_421e = { 16 76 [2] 62 6e [2] 25 6c [2] 62 7d [2] 2c 71 [2] 20 7b [2] 37 70 [2] 2c 3e [2] 11 }

  condition:
    any of them
}