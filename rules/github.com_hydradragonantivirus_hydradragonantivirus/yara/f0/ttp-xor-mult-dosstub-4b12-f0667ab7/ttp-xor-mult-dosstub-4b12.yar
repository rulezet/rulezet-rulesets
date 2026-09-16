rule TTP_XOR_MULT_DOSStub_4b12 {
  strings:
    $key_4b12 = { 1f 7a [2] 6b 62 [2] 2c 60 [2] 6b 71 [2] 25 7d [2] 29 77 [2] 3e 7c [2] 25 32 [2] 18 }

  condition:
    any of them
}