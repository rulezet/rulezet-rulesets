rule TTP_XOR_MULT_DOSStub_56ee {
  strings:
    $key_56ee = { 02 86 [2] 76 9e [2] 31 9c [2] 76 8d [2] 38 81 [2] 34 8b [2] 23 80 [2] 38 ce [2] 05 }

  condition:
    any of them
}