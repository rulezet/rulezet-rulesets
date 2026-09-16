rule TTP_XOR_MULT_DOSStub_5ce2 {
  strings:
    $key_5ce2 = { 08 8a [2] 7c 92 [2] 3b 90 [2] 7c 81 [2] 32 8d [2] 3e 87 [2] 29 8c [2] 32 c2 [2] 0f }

  condition:
    any of them
}