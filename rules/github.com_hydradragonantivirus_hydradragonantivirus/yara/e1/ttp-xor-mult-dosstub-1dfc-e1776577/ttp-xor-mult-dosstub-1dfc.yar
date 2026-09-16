rule TTP_XOR_MULT_DOSStub_1dfc {
  strings:
    $key_1dfc = { 49 94 [2] 3d 8c [2] 7a 8e [2] 3d 9f [2] 73 93 [2] 7f 99 [2] 68 92 [2] 73 dc [2] 4e }

  condition:
    any of them
}