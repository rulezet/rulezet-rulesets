rule TTP_XOR_MULT_DOSStub_794e {
  strings:
    $key_794e = { 2d 26 [2] 59 3e [2] 1e 3c [2] 59 2d [2] 17 21 [2] 1b 2b [2] 0c 20 [2] 17 6e [2] 2a }

  condition:
    any of them
}