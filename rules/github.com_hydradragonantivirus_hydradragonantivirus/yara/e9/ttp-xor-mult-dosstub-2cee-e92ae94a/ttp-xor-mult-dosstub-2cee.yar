rule TTP_XOR_MULT_DOSStub_2cee {
  strings:
    $key_2cee = { 78 86 [2] 0c 9e [2] 4b 9c [2] 0c 8d [2] 42 81 [2] 4e 8b [2] 59 80 [2] 42 ce [2] 7f }

  condition:
    any of them
}