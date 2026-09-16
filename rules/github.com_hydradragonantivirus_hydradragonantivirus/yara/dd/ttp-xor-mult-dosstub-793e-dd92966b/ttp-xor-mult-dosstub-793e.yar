rule TTP_XOR_MULT_DOSStub_793e {
  strings:
    $key_793e = { 2d 56 [2] 59 4e [2] 1e 4c [2] 59 5d [2] 17 51 [2] 1b 5b [2] 0c 50 [2] 17 1e [2] 2a }

  condition:
    any of them
}