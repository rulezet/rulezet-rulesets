rule TTP_XOR_MULT_DOSStub_5c10 {
  strings:
    $key_5c10 = { 08 78 [2] 7c 60 [2] 3b 62 [2] 7c 73 [2] 32 7f [2] 3e 75 [2] 29 7e [2] 32 30 [2] 0f }

  condition:
    any of them
}