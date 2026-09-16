rule TTP_XOR_MULT_DOSStub_78ee {
  strings:
    $key_78ee = { 2c 86 [2] 58 9e [2] 1f 9c [2] 58 8d [2] 16 81 [2] 1a 8b [2] 0d 80 [2] 16 ce [2] 2b }

  condition:
    any of them
}