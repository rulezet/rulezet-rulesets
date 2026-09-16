rule TTP_XOR_MULT_DOSStub_e068 {
  strings:
    $key_e068 = { b4 00 [2] c0 18 [2] 87 1a [2] c0 0b [2] 8e 07 [2] 82 0d [2] 95 06 [2] 8e 48 [2] b3 }

  condition:
    any of them
}