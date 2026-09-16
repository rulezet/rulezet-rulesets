rule TTP_XOR_MULT_DOSStub_4133 {
  strings:
    $key_4133 = { 15 5b [2] 61 43 [2] 26 41 [2] 61 50 [2] 2f 5c [2] 23 56 [2] 34 5d [2] 2f 13 [2] 12 }

  condition:
    any of them
}