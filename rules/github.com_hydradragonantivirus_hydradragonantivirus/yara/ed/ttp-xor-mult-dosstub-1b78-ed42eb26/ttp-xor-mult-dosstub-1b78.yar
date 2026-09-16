rule TTP_XOR_MULT_DOSStub_1b78 {
  strings:
    $key_1b78 = { 4f 10 [2] 3b 08 [2] 7c 0a [2] 3b 1b [2] 75 17 [2] 79 1d [2] 6e 16 [2] 75 58 [2] 48 }

  condition:
    any of them
}