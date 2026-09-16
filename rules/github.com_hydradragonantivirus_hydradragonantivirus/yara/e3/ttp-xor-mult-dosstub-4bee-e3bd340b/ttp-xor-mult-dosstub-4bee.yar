rule TTP_XOR_MULT_DOSStub_4bee {
  strings:
    $key_4bee = { 1f 86 [2] 6b 9e [2] 2c 9c [2] 6b 8d [2] 25 81 [2] 29 8b [2] 3e 80 [2] 25 ce [2] 18 }

  condition:
    any of them
}