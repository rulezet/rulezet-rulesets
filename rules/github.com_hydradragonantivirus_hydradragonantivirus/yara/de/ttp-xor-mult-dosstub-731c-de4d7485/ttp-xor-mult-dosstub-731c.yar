rule TTP_XOR_MULT_DOSStub_731c {
  strings:
    $key_731c = { 27 74 [2] 53 6c [2] 14 6e [2] 53 7f [2] 1d 73 [2] 11 79 [2] 06 72 [2] 1d 3c [2] 20 }

  condition:
    any of them
}