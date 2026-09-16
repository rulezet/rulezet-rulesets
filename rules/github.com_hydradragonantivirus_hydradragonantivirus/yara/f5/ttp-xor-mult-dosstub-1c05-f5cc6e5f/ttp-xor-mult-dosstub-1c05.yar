rule TTP_XOR_MULT_DOSStub_1c05 {
  strings:
    $key_1c05 = { 48 6d [2] 3c 75 [2] 7b 77 [2] 3c 66 [2] 72 6a [2] 7e 60 [2] 69 6b [2] 72 25 [2] 4f }

  condition:
    any of them
}