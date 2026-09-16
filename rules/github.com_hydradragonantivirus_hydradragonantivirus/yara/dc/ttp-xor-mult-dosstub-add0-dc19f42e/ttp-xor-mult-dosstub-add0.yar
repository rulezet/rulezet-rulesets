rule TTP_XOR_MULT_DOSStub_add0 {
  strings:
    $key_add0 = { f9 b8 [2] 8d a0 [2] ca a2 [2] 8d b3 [2] c3 bf [2] cf b5 [2] d8 be [2] c3 f0 [2] fe }

  condition:
    any of them
}