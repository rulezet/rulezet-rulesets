rule TTP_XOR_MULT_DOSStub_8ed0 {
  strings:
    $key_8ed0 = { da b8 [2] ae a0 [2] e9 a2 [2] ae b3 [2] e0 bf [2] ec b5 [2] fb be [2] e0 f0 [2] dd }

  condition:
    any of them
}