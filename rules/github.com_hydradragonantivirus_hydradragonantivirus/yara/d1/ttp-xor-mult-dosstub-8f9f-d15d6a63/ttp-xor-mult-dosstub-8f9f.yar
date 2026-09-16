rule TTP_XOR_MULT_DOSStub_8f9f {
  strings:
    $key_8f9f = { db f7 [2] af ef [2] e8 ed [2] af fc [2] e1 f0 [2] ed fa [2] fa f1 [2] e1 bf [2] dc }

  condition:
    any of them
}