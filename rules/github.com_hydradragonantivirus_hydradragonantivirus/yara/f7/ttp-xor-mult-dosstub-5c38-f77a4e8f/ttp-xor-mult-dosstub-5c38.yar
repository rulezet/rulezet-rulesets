rule TTP_XOR_MULT_DOSStub_5c38 {
  strings:
    $key_5c38 = { 08 50 [2] 7c 48 [2] 3b 4a [2] 7c 5b [2] 32 57 [2] 3e 5d [2] 29 56 [2] 32 18 [2] 0f }

  condition:
    any of them
}