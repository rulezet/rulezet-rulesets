rule TTP_XOR_MULT_DOSStub_20ee {
  strings:
    $key_20ee = { 74 86 [2] 00 9e [2] 47 9c [2] 00 8d [2] 4e 81 [2] 42 8b [2] 55 80 [2] 4e ce [2] 73 }

  condition:
    any of them
}