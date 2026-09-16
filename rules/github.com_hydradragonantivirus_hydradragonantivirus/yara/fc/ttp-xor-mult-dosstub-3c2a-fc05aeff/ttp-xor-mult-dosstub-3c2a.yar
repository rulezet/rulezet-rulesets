rule TTP_XOR_MULT_DOSStub_3c2a {
  strings:
    $key_3c2a = { 68 42 [2] 1c 5a [2] 5b 58 [2] 1c 49 [2] 52 45 [2] 5e 4f [2] 49 44 [2] 52 0a [2] 6f }

  condition:
    any of them
}