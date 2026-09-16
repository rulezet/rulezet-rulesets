rule TTP_XOR_MULT_DOSStub_4afc {
  strings:
    $key_4afc = { 1e 94 [2] 6a 8c [2] 2d 8e [2] 6a 9f [2] 24 93 [2] 28 99 [2] 3f 92 [2] 24 dc [2] 19 }

  condition:
    any of them
}