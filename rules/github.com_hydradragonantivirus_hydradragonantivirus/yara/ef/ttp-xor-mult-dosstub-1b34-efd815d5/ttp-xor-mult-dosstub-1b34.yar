rule TTP_XOR_MULT_DOSStub_1b34 {
  strings:
    $key_1b34 = { 4f 5c [2] 3b 44 [2] 7c 46 [2] 3b 57 [2] 75 5b [2] 79 51 [2] 6e 5a [2] 75 14 [2] 48 }

  condition:
    any of them
}