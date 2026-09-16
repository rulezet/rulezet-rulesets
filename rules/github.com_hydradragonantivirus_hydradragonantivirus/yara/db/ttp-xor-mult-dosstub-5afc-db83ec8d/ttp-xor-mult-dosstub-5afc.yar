rule TTP_XOR_MULT_DOSStub_5afc {
  strings:
    $key_5afc = { 0e 94 [2] 7a 8c [2] 3d 8e [2] 7a 9f [2] 34 93 [2] 38 99 [2] 2f 92 [2] 34 dc [2] 09 }

  condition:
    any of them
}