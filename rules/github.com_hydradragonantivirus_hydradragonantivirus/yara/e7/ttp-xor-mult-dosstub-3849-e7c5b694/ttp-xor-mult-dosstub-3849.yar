rule TTP_XOR_MULT_DOSStub_3849 {
  strings:
    $key_3849 = { 6c 21 [2] 18 39 [2] 5f 3b [2] 18 2a [2] 56 26 [2] 5a 2c [2] 4d 27 [2] 56 69 [2] 6b }

  condition:
    any of them
}