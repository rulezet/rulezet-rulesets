rule TTP_XOR_MULT_DOSStub_5ce6 {
  strings:
    $key_5ce6 = { 08 8e [2] 7c 96 [2] 3b 94 [2] 7c 85 [2] 32 89 [2] 3e 83 [2] 29 88 [2] 32 c6 [2] 0f }

  condition:
    any of them
}