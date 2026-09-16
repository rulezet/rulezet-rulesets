rule TTP_XOR_MULT_DOSStub_6805 {
  strings:
    $key_6805 = { 3c 6d [2] 48 75 [2] 0f 77 [2] 48 66 [2] 06 6a [2] 0a 60 [2] 1d 6b [2] 06 25 [2] 3b }

  condition:
    any of them
}