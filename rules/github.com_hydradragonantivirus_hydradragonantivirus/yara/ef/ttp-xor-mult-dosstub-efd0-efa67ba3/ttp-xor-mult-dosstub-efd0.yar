rule TTP_XOR_MULT_DOSStub_efd0 {
  strings:
    $key_efd0 = { bb b8 [2] cf a0 [2] 88 a2 [2] cf b3 [2] 81 bf [2] 8d b5 [2] 9a be [2] 81 f0 [2] bc }

  condition:
    any of them
}