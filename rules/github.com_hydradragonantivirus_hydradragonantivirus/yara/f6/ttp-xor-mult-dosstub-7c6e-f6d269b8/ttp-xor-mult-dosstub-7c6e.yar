rule TTP_XOR_MULT_DOSStub_7c6e {
  strings:
    $key_7c6e = { 28 06 [2] 5c 1e [2] 1b 1c [2] 5c 0d [2] 12 01 [2] 1e 0b [2] 09 00 [2] 12 4e [2] 2f }

  condition:
    any of them
}