rule TTP_XOR_MULT_DOSStub_7c4e {
  strings:
    $key_7c4e = { 28 26 [2] 5c 3e [2] 1b 3c [2] 5c 2d [2] 12 21 [2] 1e 2b [2] 09 20 [2] 12 6e [2] 2f }

  condition:
    any of them
}