rule TTP_XOR_MULT_DOSStub_32ee {
  strings:
    $key_32ee = { 66 86 [2] 12 9e [2] 55 9c [2] 12 8d [2] 5c 81 [2] 50 8b [2] 47 80 [2] 5c ce [2] 61 }

  condition:
    any of them
}