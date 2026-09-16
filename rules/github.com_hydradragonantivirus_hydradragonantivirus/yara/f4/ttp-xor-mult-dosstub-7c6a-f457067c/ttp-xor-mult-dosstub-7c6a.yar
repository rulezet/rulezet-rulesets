rule TTP_XOR_MULT_DOSStub_7c6a {
  strings:
    $key_7c6a = { 28 02 [2] 5c 1a [2] 1b 18 [2] 5c 09 [2] 12 05 [2] 1e 0f [2] 09 04 [2] 12 4a [2] 2f }

  condition:
    any of them
}