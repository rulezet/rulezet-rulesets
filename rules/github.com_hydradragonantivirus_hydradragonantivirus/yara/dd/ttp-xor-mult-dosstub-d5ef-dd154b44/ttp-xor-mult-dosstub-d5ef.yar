rule TTP_XOR_MULT_DOSStub_d5ef {
  strings:
    $key_d5ef = { 81 87 [2] f5 9f [2] b2 9d [2] f5 8c [2] bb 80 [2] b7 8a [2] a0 81 [2] bb cf [2] 86 }

  condition:
    any of them
}