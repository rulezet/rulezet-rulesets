rule TTP_XOR_MULT_DOSStub_3805 {
  strings:
    $key_3805 = { 6c 6d [2] 18 75 [2] 5f 77 [2] 18 66 [2] 56 6a [2] 5a 60 [2] 4d 6b [2] 56 25 [2] 6b }

  condition:
    any of them
}