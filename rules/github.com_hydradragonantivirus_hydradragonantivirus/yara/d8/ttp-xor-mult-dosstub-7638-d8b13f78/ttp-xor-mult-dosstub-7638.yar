rule TTP_XOR_MULT_DOSStub_7638 {
  strings:
    $key_7638 = { 22 50 [2] 56 48 [2] 11 4a [2] 56 5b [2] 18 57 [2] 14 5d [2] 03 56 [2] 18 18 [2] 25 }

  condition:
    any of them
}