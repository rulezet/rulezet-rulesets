rule TTP_XOR_MULT_DOSStub_8f6e {
  strings:
    $key_8f6e = { db 06 [2] af 1e [2] e8 1c [2] af 0d [2] e1 01 [2] ed 0b [2] fa 00 [2] e1 4e [2] dc }

  condition:
    any of them
}