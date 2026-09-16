rule TTP_XOR_MULT_DOSStub_7373 {
  strings:
    $key_7373 = { 27 1b [2] 53 03 [2] 14 01 [2] 53 10 [2] 1d 1c [2] 11 16 [2] 06 1d [2] 1d 53 [2] 20 }

  condition:
    any of them
}