rule TTP_XOR_MULT_DOSStub_8fe3 {
  strings:
    $key_8fe3 = { db 8b [2] af 93 [2] e8 91 [2] af 80 [2] e1 8c [2] ed 86 [2] fa 8d [2] e1 c3 [2] dc }

  condition:
    any of them
}