rule TTP_XOR_MULT_DOSStub_8f2b {
  strings:
    $key_8f2b = { db 43 [2] af 5b [2] e8 59 [2] af 48 [2] e1 44 [2] ed 4e [2] fa 45 [2] e1 0b [2] dc }

  condition:
    any of them
}