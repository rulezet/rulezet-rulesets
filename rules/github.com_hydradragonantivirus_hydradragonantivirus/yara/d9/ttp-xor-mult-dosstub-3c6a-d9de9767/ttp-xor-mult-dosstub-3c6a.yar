rule TTP_XOR_MULT_DOSStub_3c6a {
  strings:
    $key_3c6a = { 68 02 [2] 1c 1a [2] 5b 18 [2] 1c 09 [2] 52 05 [2] 5e 0f [2] 49 04 [2] 52 4a [2] 6f }

  condition:
    any of them
}