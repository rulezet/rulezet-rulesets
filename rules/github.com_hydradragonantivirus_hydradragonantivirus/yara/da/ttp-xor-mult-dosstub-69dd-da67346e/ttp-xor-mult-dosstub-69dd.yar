rule TTP_XOR_MULT_DOSStub_69dd {
  strings:
    $key_69dd = { 3d b5 [2] 49 ad [2] 0e af [2] 49 be [2] 07 b2 [2] 0b b8 [2] 1c b3 [2] 07 fd [2] 3a }

  condition:
    any of them
}