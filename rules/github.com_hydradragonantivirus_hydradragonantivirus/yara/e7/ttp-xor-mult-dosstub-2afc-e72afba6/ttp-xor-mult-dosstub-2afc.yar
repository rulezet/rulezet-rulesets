rule TTP_XOR_MULT_DOSStub_2afc {
  strings:
    $key_2afc = { 7e 94 [2] 0a 8c [2] 4d 8e [2] 0a 9f [2] 44 93 [2] 48 99 [2] 5f 92 [2] 44 dc [2] 79 }

  condition:
    any of them
}