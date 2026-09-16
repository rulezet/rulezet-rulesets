rule TTP_XOR_MULT_DOSStub_e852 {
  strings:
    $key_e852 = { bc 3a [2] c8 22 [2] 8f 20 [2] c8 31 [2] 86 3d [2] 8a 37 [2] 9d 3c [2] 86 72 [2] bb }

  condition:
    any of them
}