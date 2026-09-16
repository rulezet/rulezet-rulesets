rule TTP_XOR_MULT_DOSStub_35f8 {
  strings:
    $key_35f8 = { 61 90 [2] 15 88 [2] 52 8a [2] 15 9b [2] 5b 97 [2] 57 9d [2] 40 96 [2] 5b d8 [2] 66 }

  condition:
    any of them
}