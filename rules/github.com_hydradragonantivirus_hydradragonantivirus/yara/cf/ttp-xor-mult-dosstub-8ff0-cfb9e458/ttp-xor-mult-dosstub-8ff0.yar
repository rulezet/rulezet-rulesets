rule TTP_XOR_MULT_DOSStub_8ff0 {
  strings:
    $key_8ff0 = { db 98 [2] af 80 [2] e8 82 [2] af 93 [2] e1 9f [2] ed 95 [2] fa 9e [2] e1 d0 [2] dc }

  condition:
    any of them
}