rule TTP_XOR_MULT_DOSStub_1c74 {
  strings:
    $key_1c74 = { 48 1c [2] 3c 04 [2] 7b 06 [2] 3c 17 [2] 72 1b [2] 7e 11 [2] 69 1a [2] 72 54 [2] 4f }

  condition:
    any of them
}