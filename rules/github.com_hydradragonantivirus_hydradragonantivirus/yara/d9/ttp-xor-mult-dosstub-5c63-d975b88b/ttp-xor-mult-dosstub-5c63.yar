rule TTP_XOR_MULT_DOSStub_5c63 {
  strings:
    $key_5c63 = { 08 0b [2] 7c 13 [2] 3b 11 [2] 7c 00 [2] 32 0c [2] 3e 06 [2] 29 0d [2] 32 43 [2] 0f }

  condition:
    any of them
}