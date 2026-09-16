rule TTP_XOR_MULT_DOSStub_5c07 {
  strings:
    $key_5c07 = { 08 6f [2] 7c 77 [2] 3b 75 [2] 7c 64 [2] 32 68 [2] 3e 62 [2] 29 69 [2] 32 27 [2] 0f }

  condition:
    any of them
}