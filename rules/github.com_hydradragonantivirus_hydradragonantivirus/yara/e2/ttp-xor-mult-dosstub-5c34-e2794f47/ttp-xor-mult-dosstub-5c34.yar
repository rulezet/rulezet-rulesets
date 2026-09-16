rule TTP_XOR_MULT_DOSStub_5c34 {
  strings:
    $key_5c34 = { 08 5c [2] 7c 44 [2] 3b 46 [2] 7c 57 [2] 32 5b [2] 3e 51 [2] 29 5a [2] 32 14 [2] 0f }

  condition:
    any of them
}