rule TTP_XOR_MULT_DOSStub_736e {
  strings:
    $key_736e = { 27 06 [2] 53 1e [2] 14 1c [2] 53 0d [2] 1d 01 [2] 11 0b [2] 06 00 [2] 1d 4e [2] 20 }

  condition:
    any of them
}