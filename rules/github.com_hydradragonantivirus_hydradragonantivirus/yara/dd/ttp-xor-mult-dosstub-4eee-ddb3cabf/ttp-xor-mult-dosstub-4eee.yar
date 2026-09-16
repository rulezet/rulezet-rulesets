rule TTP_XOR_MULT_DOSStub_4eee {
  strings:
    $key_4eee = { 1a 86 [2] 6e 9e [2] 29 9c [2] 6e 8d [2] 20 81 [2] 2c 8b [2] 3b 80 [2] 20 ce [2] 1d }

  condition:
    any of them
}