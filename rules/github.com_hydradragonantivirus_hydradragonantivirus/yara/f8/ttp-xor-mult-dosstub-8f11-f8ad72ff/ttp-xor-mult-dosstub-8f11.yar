rule TTP_XOR_MULT_DOSStub_8f11 {
  strings:
    $key_8f11 = { db 79 [2] af 61 [2] e8 63 [2] af 72 [2] e1 7e [2] ed 74 [2] fa 7f [2] e1 31 [2] dc }

  condition:
    any of them
}