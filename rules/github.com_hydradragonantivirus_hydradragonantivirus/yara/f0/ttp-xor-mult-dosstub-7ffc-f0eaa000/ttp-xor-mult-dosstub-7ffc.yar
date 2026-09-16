rule TTP_XOR_MULT_DOSStub_7ffc {
  strings:
    $key_7ffc = { 2b 94 [2] 5f 8c [2] 18 8e [2] 5f 9f [2] 11 93 [2] 1d 99 [2] 0a 92 [2] 11 dc [2] 2c }

  condition:
    any of them
}