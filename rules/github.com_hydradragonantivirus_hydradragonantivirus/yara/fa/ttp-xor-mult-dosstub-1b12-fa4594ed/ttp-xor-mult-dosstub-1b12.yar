rule TTP_XOR_MULT_DOSStub_1b12 {
  strings:
    $key_1b12 = { 4f 7a [2] 3b 62 [2] 7c 60 [2] 3b 71 [2] 75 7d [2] 79 77 [2] 6e 7c [2] 75 32 [2] 48 }

  condition:
    any of them
}