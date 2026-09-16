rule TTP_XOR_MULT_DOSStub_8f1a {
  strings:
    $key_8f1a = { db 72 [2] af 6a [2] e8 68 [2] af 79 [2] e1 75 [2] ed 7f [2] fa 74 [2] e1 3a [2] dc }

  condition:
    any of them
}