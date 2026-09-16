rule TTP_XOR_MULT_DOSStub_8f05 {
  strings:
    $key_8f05 = { db 6d [2] af 75 [2] e8 77 [2] af 66 [2] e1 6a [2] ed 60 [2] fa 6b [2] e1 25 [2] dc }

  condition:
    any of them
}