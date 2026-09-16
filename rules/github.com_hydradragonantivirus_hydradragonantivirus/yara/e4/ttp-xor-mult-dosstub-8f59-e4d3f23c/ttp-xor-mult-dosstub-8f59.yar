rule TTP_XOR_MULT_DOSStub_8f59 {
  strings:
    $key_8f59 = { db 31 [2] af 29 [2] e8 2b [2] af 3a [2] e1 36 [2] ed 3c [2] fa 37 [2] e1 79 [2] dc }

  condition:
    any of them
}