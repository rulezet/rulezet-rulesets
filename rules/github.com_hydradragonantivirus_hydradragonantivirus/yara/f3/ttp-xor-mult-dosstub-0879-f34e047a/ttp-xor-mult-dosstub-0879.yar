rule TTP_XOR_MULT_DOSStub_0879 {
  strings:
    $key_0879 = { 5c 11 [2] 28 09 [2] 6f 0b [2] 28 1a [2] 66 16 [2] 6a 1c [2] 7d 17 [2] 66 59 [2] 5b }

  condition:
    any of them
}