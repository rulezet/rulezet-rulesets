rule TTP_XOR_MULT_DOSStub_3efc {
  strings:
    $key_3efc = { 6a 94 [2] 1e 8c [2] 59 8e [2] 1e 9f [2] 50 93 [2] 5c 99 [2] 4b 92 [2] 50 dc [2] 6d }

  condition:
    any of them
}