rule TTP_XOR_MULT_DOSStub_8f15 {
  strings:
    $key_8f15 = { db 7d [2] af 65 [2] e8 67 [2] af 76 [2] e1 7a [2] ed 70 [2] fa 7b [2] e1 35 [2] dc }

  condition:
    any of them
}