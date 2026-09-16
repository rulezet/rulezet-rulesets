rule TTP_XOR_MULT_DOSStub_7814 {
  strings:
    $key_7814 = { 2c 7c [2] 58 64 [2] 1f 66 [2] 58 77 [2] 16 7b [2] 1a 71 [2] 0d 7a [2] 16 34 [2] 2b }

  condition:
    any of them
}