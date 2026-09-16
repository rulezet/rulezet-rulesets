rule TTP_XOR_MULT_DOSStub_1c38 {
  strings:
    $key_1c38 = { 48 50 [2] 3c 48 [2] 7b 4a [2] 3c 5b [2] 72 57 [2] 7e 5d [2] 69 56 [2] 72 18 [2] 4f }

  condition:
    any of them
}