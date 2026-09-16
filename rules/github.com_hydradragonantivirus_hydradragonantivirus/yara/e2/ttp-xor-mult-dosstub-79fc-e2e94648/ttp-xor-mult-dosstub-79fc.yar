rule TTP_XOR_MULT_DOSStub_79fc {
  strings:
    $key_79fc = { 2d 94 [2] 59 8c [2] 1e 8e [2] 59 9f [2] 17 93 [2] 1b 99 [2] 0c 92 [2] 17 dc [2] 2a }

  condition:
    any of them
}