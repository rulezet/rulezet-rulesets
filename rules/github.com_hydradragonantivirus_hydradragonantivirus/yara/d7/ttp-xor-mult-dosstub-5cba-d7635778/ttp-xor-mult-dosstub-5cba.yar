rule TTP_XOR_MULT_DOSStub_5cba {
  strings:
    $key_5cba = { 08 d2 [2] 7c ca [2] 3b c8 [2] 7c d9 [2] 32 d5 [2] 3e df [2] 29 d4 [2] 32 9a [2] 0f }

  condition:
    any of them
}