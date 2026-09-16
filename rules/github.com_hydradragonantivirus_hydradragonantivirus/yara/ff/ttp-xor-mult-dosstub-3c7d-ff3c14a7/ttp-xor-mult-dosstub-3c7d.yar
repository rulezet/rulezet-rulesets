rule TTP_XOR_MULT_DOSStub_3c7d {
  strings:
    $key_3c7d = { 68 15 [2] 1c 0d [2] 5b 0f [2] 1c 1e [2] 52 12 [2] 5e 18 [2] 49 13 [2] 52 5d [2] 6f }

  condition:
    any of them
}