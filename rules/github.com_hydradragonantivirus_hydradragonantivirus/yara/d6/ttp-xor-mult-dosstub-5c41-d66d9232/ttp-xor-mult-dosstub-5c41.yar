rule TTP_XOR_MULT_DOSStub_5c41 {
  strings:
    $key_5c41 = { 08 29 [2] 7c 31 [2] 3b 33 [2] 7c 22 [2] 32 2e [2] 3e 24 [2] 29 2f [2] 32 61 [2] 0f }

  condition:
    any of them
}