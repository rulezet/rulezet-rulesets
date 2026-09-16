rule TTP_XOR_MULT_DOSStub_46ee {
  strings:
    $key_46ee = { 12 86 [2] 66 9e [2] 21 9c [2] 66 8d [2] 28 81 [2] 24 8b [2] 33 80 [2] 28 ce [2] 15 }

  condition:
    any of them
}