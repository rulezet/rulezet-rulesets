rule TTP_XOR_MULT_DOSStub_5133 {
  strings:
    $key_5133 = { 05 5b [2] 71 43 [2] 36 41 [2] 71 50 [2] 3f 5c [2] 33 56 [2] 24 5d [2] 3f 13 [2] 02 }

  condition:
    any of them
}