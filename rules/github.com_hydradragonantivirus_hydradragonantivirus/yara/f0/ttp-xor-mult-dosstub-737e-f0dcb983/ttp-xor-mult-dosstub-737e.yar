rule TTP_XOR_MULT_DOSStub_737e {
  strings:
    $key_737e = { 27 16 [2] 53 0e [2] 14 0c [2] 53 1d [2] 1d 11 [2] 11 1b [2] 06 10 [2] 1d 5e [2] 20 }

  condition:
    any of them
}