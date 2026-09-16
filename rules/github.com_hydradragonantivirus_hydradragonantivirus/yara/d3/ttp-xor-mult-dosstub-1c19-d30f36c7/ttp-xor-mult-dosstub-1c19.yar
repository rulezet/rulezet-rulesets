rule TTP_XOR_MULT_DOSStub_1c19 {
  strings:
    $key_1c19 = { 48 71 [2] 3c 69 [2] 7b 6b [2] 3c 7a [2] 72 76 [2] 7e 7c [2] 69 77 [2] 72 39 [2] 4f }

  condition:
    any of them
}