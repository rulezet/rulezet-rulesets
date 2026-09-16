rule TTP_XOR_MULT_DOSStub_7838 {
  strings:
    $key_7838 = { 2c 50 [2] 58 48 [2] 1f 4a [2] 58 5b [2] 16 57 [2] 1a 5d [2] 0d 56 [2] 16 18 [2] 2b }

  condition:
    any of them
}