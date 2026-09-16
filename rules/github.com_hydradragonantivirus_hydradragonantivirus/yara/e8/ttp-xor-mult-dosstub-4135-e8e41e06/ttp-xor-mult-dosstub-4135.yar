rule TTP_XOR_MULT_DOSStub_4135 {
  strings:
    $key_4135 = { 15 5d [2] 61 45 [2] 26 47 [2] 61 56 [2] 2f 5a [2] 23 50 [2] 34 5b [2] 2f 15 [2] 12 }

  condition:
    any of them
}