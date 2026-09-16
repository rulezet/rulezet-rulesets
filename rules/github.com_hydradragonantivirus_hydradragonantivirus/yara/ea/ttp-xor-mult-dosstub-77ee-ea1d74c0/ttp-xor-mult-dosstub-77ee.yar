rule TTP_XOR_MULT_DOSStub_77ee {
  strings:
    $key_77ee = { 23 86 [2] 57 9e [2] 10 9c [2] 57 8d [2] 19 81 [2] 15 8b [2] 02 80 [2] 19 ce [2] 24 }

  condition:
    any of them
}