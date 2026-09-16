rule TTP_XOR_MULT_DOSStub_5c5a {
  strings:
    $key_5c5a = { 08 32 [2] 7c 2a [2] 3b 28 [2] 7c 39 [2] 32 35 [2] 3e 3f [2] 29 34 [2] 32 7a [2] 0f }

  condition:
    any of them
}