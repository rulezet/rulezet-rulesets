rule TTP_XOR_MULT_DOSStub_61dd {
  strings:
    $key_61dd = { 35 b5 [2] 41 ad [2] 06 af [2] 41 be [2] 0f b2 [2] 03 b8 [2] 14 b3 [2] 0f fd [2] 32 }

  condition:
    any of them
}