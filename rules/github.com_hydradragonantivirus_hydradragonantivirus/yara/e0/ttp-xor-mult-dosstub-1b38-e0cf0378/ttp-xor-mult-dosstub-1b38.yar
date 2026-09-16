rule TTP_XOR_MULT_DOSStub_1b38 {
  strings:
    $key_1b38 = { 4f 50 [2] 3b 48 [2] 7c 4a [2] 3b 5b [2] 75 57 [2] 79 5d [2] 6e 56 [2] 75 18 [2] 48 }

  condition:
    any of them
}