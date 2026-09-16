rule TTP_XOR_MULT_DOSStub_8f55 {
  strings:
    $key_8f55 = { db 3d [2] af 25 [2] e8 27 [2] af 36 [2] e1 3a [2] ed 30 [2] fa 3b [2] e1 75 [2] dc }

  condition:
    any of them
}