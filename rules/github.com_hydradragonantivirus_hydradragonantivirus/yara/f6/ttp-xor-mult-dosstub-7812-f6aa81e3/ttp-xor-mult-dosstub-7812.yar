rule TTP_XOR_MULT_DOSStub_7812 {
  strings:
    $key_7812 = { 2c 7a [2] 58 62 [2] 1f 60 [2] 58 71 [2] 16 7d [2] 1a 77 [2] 0d 7c [2] 16 32 [2] 2b }

  condition:
    any of them
}