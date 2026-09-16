rule TTP_XOR_MULT_DOSStub_25f8 {
  strings:
    $key_25f8 = { 71 90 [2] 05 88 [2] 42 8a [2] 05 9b [2] 4b 97 [2] 47 9d [2] 50 96 [2] 4b d8 [2] 76 }

  condition:
    any of them
}