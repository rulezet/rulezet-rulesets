rule TTP_XOR_MULT_DOSStub_c7ee {
  strings:
    $key_c7ee = { 93 86 [2] e7 9e [2] a0 9c [2] e7 8d [2] a9 81 [2] a5 8b [2] b2 80 [2] a9 ce [2] 94 }

  condition:
    any of them
}