rule TTP_XOR_MULT_DOSStub_8f47 {
  strings:
    $key_8f47 = { db 2f [2] af 37 [2] e8 35 [2] af 24 [2] e1 28 [2] ed 22 [2] fa 29 [2] e1 67 [2] dc }

  condition:
    any of them
}