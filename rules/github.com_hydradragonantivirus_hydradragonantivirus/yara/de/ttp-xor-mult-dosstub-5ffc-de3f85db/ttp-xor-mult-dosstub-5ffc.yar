rule TTP_XOR_MULT_DOSStub_5ffc {
  strings:
    $key_5ffc = { 0b 94 [2] 7f 8c [2] 38 8e [2] 7f 9f [2] 31 93 [2] 3d 99 [2] 2a 92 [2] 31 dc [2] 0c }

  condition:
    any of them
}