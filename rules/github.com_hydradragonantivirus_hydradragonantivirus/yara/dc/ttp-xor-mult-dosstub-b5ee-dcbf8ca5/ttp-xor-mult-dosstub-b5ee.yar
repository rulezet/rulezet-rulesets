rule TTP_XOR_MULT_DOSStub_b5ee {
  strings:
    $key_b5ee = { e1 86 [2] 95 9e [2] d2 9c [2] 95 8d [2] db 81 [2] d7 8b [2] c0 80 [2] db ce [2] e6 }

  condition:
    any of them
}