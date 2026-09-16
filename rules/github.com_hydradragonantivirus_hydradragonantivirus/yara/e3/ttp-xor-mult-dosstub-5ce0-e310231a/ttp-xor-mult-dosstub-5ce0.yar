rule TTP_XOR_MULT_DOSStub_5ce0 {
  strings:
    $key_5ce0 = { 08 88 [2] 7c 90 [2] 3b 92 [2] 7c 83 [2] 32 8f [2] 3e 85 [2] 29 8e [2] 32 c0 [2] 0f }

  condition:
    any of them
}