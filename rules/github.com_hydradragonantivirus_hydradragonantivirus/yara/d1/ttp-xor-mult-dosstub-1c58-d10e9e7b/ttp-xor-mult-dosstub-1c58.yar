rule TTP_XOR_MULT_DOSStub_1c58 {
  strings:
    $key_1c58 = { 48 30 [2] 3c 28 [2] 7b 2a [2] 3c 3b [2] 72 37 [2] 7e 3d [2] 69 36 [2] 72 78 [2] 4f }

  condition:
    any of them
}