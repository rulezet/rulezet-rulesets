rule TTP_XOR_MULT_DOSStub_8f7a {
  strings:
    $key_8f7a = { db 12 [2] af 0a [2] e8 08 [2] af 19 [2] e1 15 [2] ed 1f [2] fa 14 [2] e1 5a [2] dc }

  condition:
    any of them
}