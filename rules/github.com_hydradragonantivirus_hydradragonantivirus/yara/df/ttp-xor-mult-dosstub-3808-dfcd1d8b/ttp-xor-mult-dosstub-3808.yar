rule TTP_XOR_MULT_DOSStub_3808 {
  strings:
    $key_3808 = { 6c 60 [2] 18 78 [2] 5f 7a [2] 18 6b [2] 56 67 [2] 5a 6d [2] 4d 66 [2] 56 28 [2] 6b }

  condition:
    any of them
}