rule TTP_XOR_MULT_DOSStub_8ff6 {
  strings:
    $key_8ff6 = { db 9e [2] af 86 [2] e8 84 [2] af 95 [2] e1 99 [2] ed 93 [2] fa 98 [2] e1 d6 [2] dc }

  condition:
    any of them
}