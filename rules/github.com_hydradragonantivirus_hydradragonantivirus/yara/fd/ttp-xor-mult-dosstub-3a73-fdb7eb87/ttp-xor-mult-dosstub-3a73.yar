rule TTP_XOR_MULT_DOSStub_3a73 {
  strings:
    $key_3a73 = { 6e 1b [2] 1a 03 [2] 5d 01 [2] 1a 10 [2] 54 1c [2] 58 16 [2] 4f 1d [2] 54 53 [2] 69 }

  condition:
    any of them
}