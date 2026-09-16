rule TTP_XOR_MULT_DOSStub_8f6f {
  strings:
    $key_8f6f = { db 07 [2] af 1f [2] e8 1d [2] af 0c [2] e1 00 [2] ed 0a [2] fa 01 [2] e1 4f [2] dc }

  condition:
    any of them
}