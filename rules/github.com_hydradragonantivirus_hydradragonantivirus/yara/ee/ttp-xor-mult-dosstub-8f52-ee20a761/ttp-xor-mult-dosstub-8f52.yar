rule TTP_XOR_MULT_DOSStub_8f52 {
  strings:
    $key_8f52 = { db 3a [2] af 22 [2] e8 20 [2] af 31 [2] e1 3d [2] ed 37 [2] fa 3c [2] e1 72 [2] dc }

  condition:
    any of them
}