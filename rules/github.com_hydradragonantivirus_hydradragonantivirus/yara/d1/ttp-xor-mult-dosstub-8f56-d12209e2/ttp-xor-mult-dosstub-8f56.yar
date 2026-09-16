rule TTP_XOR_MULT_DOSStub_8f56 {
  strings:
    $key_8f56 = { db 3e [2] af 26 [2] e8 24 [2] af 35 [2] e1 39 [2] ed 33 [2] fa 38 [2] e1 76 [2] dc }

  condition:
    any of them
}