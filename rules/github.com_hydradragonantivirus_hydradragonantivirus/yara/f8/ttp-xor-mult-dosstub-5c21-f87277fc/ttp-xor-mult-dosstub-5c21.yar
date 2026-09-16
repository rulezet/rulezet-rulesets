rule TTP_XOR_MULT_DOSStub_5c21 {
  strings:
    $key_5c21 = { 08 49 [2] 7c 51 [2] 3b 53 [2] 7c 42 [2] 32 4e [2] 3e 44 [2] 29 4f [2] 32 01 [2] 0f }

  condition:
    any of them
}