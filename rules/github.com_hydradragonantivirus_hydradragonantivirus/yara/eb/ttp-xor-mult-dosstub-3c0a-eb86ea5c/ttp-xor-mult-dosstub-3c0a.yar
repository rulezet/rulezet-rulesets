rule TTP_XOR_MULT_DOSStub_3c0a {
  strings:
    $key_3c0a = { 68 62 [2] 1c 7a [2] 5b 78 [2] 1c 69 [2] 52 65 [2] 5e 6f [2] 49 64 [2] 52 2a [2] 6f }

  condition:
    any of them
}