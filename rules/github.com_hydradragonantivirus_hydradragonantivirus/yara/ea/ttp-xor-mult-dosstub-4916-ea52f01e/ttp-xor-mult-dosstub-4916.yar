rule TTP_XOR_MULT_DOSStub_4916 {
  strings:
    $key_4916 = { 1d 7e [2] 69 66 [2] 2e 64 [2] 69 75 [2] 27 79 [2] 2b 73 [2] 3c 78 [2] 27 36 [2] 1a }

  condition:
    any of them
}