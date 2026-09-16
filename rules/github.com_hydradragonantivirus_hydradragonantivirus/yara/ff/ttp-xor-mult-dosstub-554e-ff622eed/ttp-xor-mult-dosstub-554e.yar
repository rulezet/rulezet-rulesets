rule TTP_XOR_MULT_DOSStub_554e {
  strings:
    $key_554e = { 01 26 [2] 75 3e [2] 32 3c [2] 75 2d [2] 3b 21 [2] 37 2b [2] 20 20 [2] 3b 6e [2] 06 }

  condition:
    any of them
}