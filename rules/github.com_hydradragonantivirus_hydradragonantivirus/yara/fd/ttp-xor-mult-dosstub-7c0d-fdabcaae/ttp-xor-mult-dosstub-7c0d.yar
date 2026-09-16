rule TTP_XOR_MULT_DOSStub_7c0d {
  strings:
    $key_7c0d = { 28 65 [2] 5c 7d [2] 1b 7f [2] 5c 6e [2] 12 62 [2] 1e 68 [2] 09 63 [2] 12 2d [2] 2f }

  condition:
    any of them
}