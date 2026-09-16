rule TTP_XOR_MULT_DOSStub_8f58 {
  strings:
    $key_8f58 = { db 30 [2] af 28 [2] e8 2a [2] af 3b [2] e1 37 [2] ed 3d [2] fa 36 [2] e1 78 [2] dc }

  condition:
    any of them
}