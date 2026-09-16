rule TTP_XOR_MULT_DOSStub_3874 {
  strings:
    $key_3874 = { 6c 1c [2] 18 04 [2] 5f 06 [2] 18 17 [2] 56 1b [2] 5a 11 [2] 4d 1a [2] 56 54 [2] 6b }

  condition:
    any of them
}