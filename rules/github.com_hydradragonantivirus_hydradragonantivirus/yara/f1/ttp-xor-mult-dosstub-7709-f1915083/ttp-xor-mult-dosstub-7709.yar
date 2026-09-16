rule TTP_XOR_MULT_DOSStub_7709 {
  strings:
    $key_7709 = { 23 61 [2] 57 79 [2] 10 7b [2] 57 6a [2] 19 66 [2] 15 6c [2] 02 67 [2] 19 29 [2] 24 }

  condition:
    any of them
}