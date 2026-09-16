rule TTP_XOR_MULT_DOSStub_cf9f {
  strings:
    $key_cf9f = { 9b f7 [2] ef ef [2] a8 ed [2] ef fc [2] a1 f0 [2] ad fa [2] ba f1 [2] a1 bf [2] 9c }

  condition:
    any of them
}