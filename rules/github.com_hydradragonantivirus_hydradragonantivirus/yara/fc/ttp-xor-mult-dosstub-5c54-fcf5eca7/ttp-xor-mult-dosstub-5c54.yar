rule TTP_XOR_MULT_DOSStub_5c54 {
  strings:
    $key_5c54 = { 08 3c [2] 7c 24 [2] 3b 26 [2] 7c 37 [2] 32 3b [2] 3e 31 [2] 29 3a [2] 32 74 [2] 0f }

  condition:
    any of them
}