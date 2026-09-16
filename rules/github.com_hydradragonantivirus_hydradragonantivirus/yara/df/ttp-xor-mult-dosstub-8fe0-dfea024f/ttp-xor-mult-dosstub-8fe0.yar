rule TTP_XOR_MULT_DOSStub_8fe0 {
  strings:
    $key_8fe0 = { db 88 [2] af 90 [2] e8 92 [2] af 83 [2] e1 8f [2] ed 85 [2] fa 8e [2] e1 c0 [2] dc }

  condition:
    any of them
}