rule TTP_XOR_MULT_DOSStub_8f0a {
  strings:
    $key_8f0a = { db 62 [2] af 7a [2] e8 78 [2] af 69 [2] e1 65 [2] ed 6f [2] fa 64 [2] e1 2a [2] dc }

  condition:
    any of them
}