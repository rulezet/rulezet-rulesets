rule TTP_XOR_MULT_DOSStub_5c4e {
  strings:
    $key_5c4e = { 08 26 [2] 7c 3e [2] 3b 3c [2] 7c 2d [2] 32 21 [2] 3e 2b [2] 29 20 [2] 32 6e [2] 0f }

  condition:
    any of them
}