rule TTP_XOR_MULT_DOSStub_8ffa {
  strings:
    $key_8ffa = { db 92 [2] af 8a [2] e8 88 [2] af 99 [2] e1 95 [2] ed 9f [2] fa 94 [2] e1 da [2] dc }

  condition:
    any of them
}