rule TTP_XOR_MULT_DOSStub_02f8 {
  strings:
    $key_02f8 = { 56 90 [2] 22 88 [2] 65 8a [2] 22 9b [2] 6c 97 [2] 60 9d [2] 77 96 [2] 6c d8 [2] 51 }

  condition:
    any of them
}