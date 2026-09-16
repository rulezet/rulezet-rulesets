rule TTP_XOR_MULT_DOSStub_0bfc {
  strings:
    $key_0bfc = { 5f 94 [2] 2b 8c [2] 6c 8e [2] 2b 9f [2] 65 93 [2] 69 99 [2] 7e 92 [2] 65 dc [2] 58 }

  condition:
    any of them
}