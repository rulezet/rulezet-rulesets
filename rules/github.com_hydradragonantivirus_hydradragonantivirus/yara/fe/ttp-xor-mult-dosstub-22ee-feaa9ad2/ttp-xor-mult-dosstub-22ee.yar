rule TTP_XOR_MULT_DOSStub_22ee {
  strings:
    $key_22ee = { 76 86 [2] 02 9e [2] 45 9c [2] 02 8d [2] 4c 81 [2] 40 8b [2] 57 80 [2] 4c ce [2] 71 }

  condition:
    any of them
}