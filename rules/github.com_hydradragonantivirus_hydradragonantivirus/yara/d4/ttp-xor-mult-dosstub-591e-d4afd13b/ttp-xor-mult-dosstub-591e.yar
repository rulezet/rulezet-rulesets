rule TTP_XOR_MULT_DOSStub_591e {
  strings:
    $key_591e = { 0d 76 [2] 79 6e [2] 3e 6c [2] 79 7d [2] 37 71 [2] 3b 7b [2] 2c 70 [2] 37 3e [2] 0a }

  condition:
    any of them
}