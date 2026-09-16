rule TTP_XOR_MULT_DOSStub_3373 {
  strings:
    $key_3373 = { 67 1b [2] 13 03 [2] 54 01 [2] 13 10 [2] 5d 1c [2] 51 16 [2] 46 1d [2] 5d 53 [2] 60 }

  condition:
    any of them
}