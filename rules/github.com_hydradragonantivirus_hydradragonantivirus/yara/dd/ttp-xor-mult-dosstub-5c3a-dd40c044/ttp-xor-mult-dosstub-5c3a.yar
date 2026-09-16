rule TTP_XOR_MULT_DOSStub_5c3a {
  strings:
    $key_5c3a = { 08 52 [2] 7c 4a [2] 3b 48 [2] 7c 59 [2] 32 55 [2] 3e 5f [2] 29 54 [2] 32 1a [2] 0f }

  condition:
    any of them
}