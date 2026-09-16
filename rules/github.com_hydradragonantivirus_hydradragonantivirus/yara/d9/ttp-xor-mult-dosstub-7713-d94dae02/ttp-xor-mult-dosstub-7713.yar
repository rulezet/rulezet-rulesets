rule TTP_XOR_MULT_DOSStub_7713 {
  strings:
    $key_7713 = { 23 7b [2] 57 63 [2] 10 61 [2] 57 70 [2] 19 7c [2] 15 76 [2] 02 7d [2] 19 33 [2] 24 }

  condition:
    any of them
}