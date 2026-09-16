rule TTP_XOR_MULT_DOSStub_641e {
  strings:
    $key_641e = { 30 76 [2] 44 6e [2] 03 6c [2] 44 7d [2] 0a 71 [2] 06 7b [2] 11 70 [2] 0a 3e [2] 37 }

  condition:
    any of them
}