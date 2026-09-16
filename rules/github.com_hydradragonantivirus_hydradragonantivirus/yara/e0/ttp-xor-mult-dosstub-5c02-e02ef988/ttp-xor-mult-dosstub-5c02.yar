rule TTP_XOR_MULT_DOSStub_5c02 {
  strings:
    $key_5c02 = { 08 6a [2] 7c 72 [2] 3b 70 [2] 7c 61 [2] 32 6d [2] 3e 67 [2] 29 6c [2] 32 22 [2] 0f }

  condition:
    any of them
}