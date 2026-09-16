rule TTP_XOR_MULT_DOSStub_521e {
  strings:
    $key_521e = { 06 76 [2] 72 6e [2] 35 6c [2] 72 7d [2] 3c 71 [2] 30 7b [2] 27 70 [2] 3c 3e [2] 01 }

  condition:
    any of them
}