rule TTP_XOR_MULT_DOSStub_8f64 {
  strings:
    $key_8f64 = { db 0c [2] af 14 [2] e8 16 [2] af 07 [2] e1 0b [2] ed 01 [2] fa 0a [2] e1 44 [2] dc }

  condition:
    any of them
}