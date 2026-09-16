rule TTP_XOR_MULT_DOSStub_8fef {
  strings:
    $key_8fef = { db 87 [2] af 9f [2] e8 9d [2] af 8c [2] e1 80 [2] ed 8a [2] fa 81 [2] e1 cf [2] dc }

  condition:
    any of them
}