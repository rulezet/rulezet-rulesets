rule TTP_XOR_MULT_DOSStub_731b {
  strings:
    $key_731b = { 27 73 [2] 53 6b [2] 14 69 [2] 53 78 [2] 1d 74 [2] 11 7e [2] 06 75 [2] 1d 3b [2] 20 }

  condition:
    any of them
}