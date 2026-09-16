rule TTP_XOR_MULT_DOSStub_3376 {
  strings:
    $key_3376 = { 67 1e [2] 13 06 [2] 54 04 [2] 13 15 [2] 5d 19 [2] 51 13 [2] 46 18 [2] 5d 56 [2] 60 }

  condition:
    any of them
}