rule TTP_XOR_MULT_DOSStub_1c08 {
  strings:
    $key_1c08 = { 48 60 [2] 3c 78 [2] 7b 7a [2] 3c 6b [2] 72 67 [2] 7e 6d [2] 69 66 [2] 72 28 [2] 4f }

  condition:
    any of them
}