rule TTP_XOR_MULT_DOSStub_8ff2 {
  strings:
    $key_8ff2 = { db 9a [2] af 82 [2] e8 80 [2] af 91 [2] e1 9d [2] ed 97 [2] fa 9c [2] e1 d2 [2] dc }

  condition:
    any of them
}