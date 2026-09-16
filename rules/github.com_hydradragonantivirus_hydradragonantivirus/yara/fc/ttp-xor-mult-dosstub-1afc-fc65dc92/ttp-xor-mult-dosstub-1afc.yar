rule TTP_XOR_MULT_DOSStub_1afc {
  strings:
    $key_1afc = { 4e 94 [2] 3a 8c [2] 7d 8e [2] 3a 9f [2] 74 93 [2] 78 99 [2] 6f 92 [2] 74 dc [2] 49 }

  condition:
    any of them
}