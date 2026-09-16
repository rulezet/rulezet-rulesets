rule TTP_XOR_MULT_DOSStub_7c2d {
  strings:
    $key_7c2d = { 28 45 [2] 5c 5d [2] 1b 5f [2] 5c 4e [2] 12 42 [2] 1e 48 [2] 09 43 [2] 12 0d [2] 2f }

  condition:
    any of them
}