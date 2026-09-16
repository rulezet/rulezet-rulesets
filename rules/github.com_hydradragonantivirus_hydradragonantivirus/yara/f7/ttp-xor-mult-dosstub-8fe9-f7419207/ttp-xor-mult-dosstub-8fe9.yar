rule TTP_XOR_MULT_DOSStub_8fe9 {
  strings:
    $key_8fe9 = { db 81 [2] af 99 [2] e8 9b [2] af 8a [2] e1 86 [2] ed 8c [2] fa 87 [2] e1 c9 [2] dc }

  condition:
    any of them
}