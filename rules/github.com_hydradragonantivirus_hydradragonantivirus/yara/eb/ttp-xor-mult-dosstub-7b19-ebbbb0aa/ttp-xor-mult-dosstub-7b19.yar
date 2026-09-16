rule TTP_XOR_MULT_DOSStub_7b19 {
  strings:
    $key_7b19 = { 2f 71 [2] 5b 69 [2] 1c 6b [2] 5b 7a [2] 15 76 [2] 19 7c [2] 0e 77 [2] 15 39 [2] 28 }

  condition:
    any of them
}