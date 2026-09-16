rule TTP_XOR_MULT_DOSStub_5ce5 {
  strings:
    $key_5ce5 = { 08 8d [2] 7c 95 [2] 3b 97 [2] 7c 86 [2] 32 8a [2] 3e 80 [2] 29 8b [2] 32 c5 [2] 0f }

  condition:
    any of them
}