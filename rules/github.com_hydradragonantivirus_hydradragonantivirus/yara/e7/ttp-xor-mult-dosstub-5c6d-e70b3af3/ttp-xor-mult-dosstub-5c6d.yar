rule TTP_XOR_MULT_DOSStub_5c6d {
  strings:
    $key_5c6d = { 08 05 [2] 7c 1d [2] 3b 1f [2] 7c 0e [2] 32 02 [2] 3e 08 [2] 29 03 [2] 32 4d [2] 0f }

  condition:
    any of them
}