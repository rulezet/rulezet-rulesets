rule TTP_XOR_MULT_DOSStub_1b19 {
  strings:
    $key_1b19 = { 4f 71 [2] 3b 69 [2] 7c 6b [2] 3b 7a [2] 75 76 [2] 79 7c [2] 6e 77 [2] 75 39 [2] 48 }

  condition:
    any of them
}