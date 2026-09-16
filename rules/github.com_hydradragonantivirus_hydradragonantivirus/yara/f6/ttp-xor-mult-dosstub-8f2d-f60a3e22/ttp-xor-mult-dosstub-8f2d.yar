rule TTP_XOR_MULT_DOSStub_8f2d {
  strings:
    $key_8f2d = { db 45 [2] af 5d [2] e8 5f [2] af 4e [2] e1 42 [2] ed 48 [2] fa 43 [2] e1 0d [2] dc }

  condition:
    any of them
}