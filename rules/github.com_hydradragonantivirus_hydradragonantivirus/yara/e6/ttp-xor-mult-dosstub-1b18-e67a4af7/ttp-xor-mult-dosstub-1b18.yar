rule TTP_XOR_MULT_DOSStub_1b18 {
  strings:
    $key_1b18 = { 4f 70 [2] 3b 68 [2] 7c 6a [2] 3b 7b [2] 75 77 [2] 79 7d [2] 6e 76 [2] 75 38 [2] 48 }

  condition:
    any of them
}