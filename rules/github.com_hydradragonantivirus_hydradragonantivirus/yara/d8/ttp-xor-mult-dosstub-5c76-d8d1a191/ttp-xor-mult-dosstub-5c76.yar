rule TTP_XOR_MULT_DOSStub_5c76 {
  strings:
    $key_5c76 = { 08 1e [2] 7c 06 [2] 3b 04 [2] 7c 15 [2] 32 19 [2] 3e 13 [2] 29 18 [2] 32 56 [2] 0f }

  condition:
    any of them
}