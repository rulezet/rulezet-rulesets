rule TTP_XOR_MULT_DOSStub_731e {
  strings:
    $key_731e = { 27 76 [2] 53 6e [2] 14 6c [2] 53 7d [2] 1d 71 [2] 11 7b [2] 06 70 [2] 1d 3e [2] 20 }

  condition:
    any of them
}