rule TTP_XOR_MULT_DOSStub_8ff7 {
  strings:
    $key_8ff7 = { db 9f [2] af 87 [2] e8 85 [2] af 94 [2] e1 98 [2] ed 92 [2] fa 99 [2] e1 d7 [2] dc }

  condition:
    any of them
}