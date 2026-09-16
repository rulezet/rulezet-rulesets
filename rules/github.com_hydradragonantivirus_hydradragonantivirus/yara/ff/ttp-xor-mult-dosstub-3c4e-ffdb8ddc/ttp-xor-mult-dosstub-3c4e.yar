rule TTP_XOR_MULT_DOSStub_3c4e {
  strings:
    $key_3c4e = { 68 26 [2] 1c 3e [2] 5b 3c [2] 1c 2d [2] 52 21 [2] 5e 2b [2] 49 20 [2] 52 6e [2] 6f }

  condition:
    any of them
}