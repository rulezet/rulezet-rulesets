rule TTP_XOR_MULT_DOSStub_8f75 {
  strings:
    $key_8f75 = { db 1d [2] af 05 [2] e8 07 [2] af 16 [2] e1 1a [2] ed 10 [2] fa 1b [2] e1 55 [2] dc }

  condition:
    any of them
}