rule TTP_XOR_MULT_DOSStub_5c15 {
  strings:
    $key_5c15 = { 08 7d [2] 7c 65 [2] 3b 67 [2] 7c 76 [2] 32 7a [2] 3e 70 [2] 29 7b [2] 32 35 [2] 0f }

  condition:
    any of them
}