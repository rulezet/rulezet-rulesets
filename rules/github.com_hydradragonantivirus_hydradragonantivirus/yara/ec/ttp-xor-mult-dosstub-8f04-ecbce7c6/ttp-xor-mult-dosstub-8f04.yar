rule TTP_XOR_MULT_DOSStub_8f04 {
  strings:
    $key_8f04 = { db 6c [2] af 74 [2] e8 76 [2] af 67 [2] e1 6b [2] ed 61 [2] fa 6a [2] e1 24 [2] dc }

  condition:
    any of them
}