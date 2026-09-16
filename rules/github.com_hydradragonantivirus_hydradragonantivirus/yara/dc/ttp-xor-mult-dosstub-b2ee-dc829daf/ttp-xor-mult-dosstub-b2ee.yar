rule TTP_XOR_MULT_DOSStub_b2ee {
  strings:
    $key_b2ee = { e6 86 [2] 92 9e [2] d5 9c [2] 92 8d [2] dc 81 [2] d0 8b [2] c7 80 [2] dc ce [2] e1 }

  condition:
    any of them
}