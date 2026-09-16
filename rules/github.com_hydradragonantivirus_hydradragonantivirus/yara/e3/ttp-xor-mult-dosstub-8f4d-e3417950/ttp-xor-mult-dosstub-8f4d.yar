rule TTP_XOR_MULT_DOSStub_8f4d {
  strings:
    $key_8f4d = { db 25 [2] af 3d [2] e8 3f [2] af 2e [2] e1 22 [2] ed 28 [2] fa 23 [2] e1 6d [2] dc }

  condition:
    any of them
}