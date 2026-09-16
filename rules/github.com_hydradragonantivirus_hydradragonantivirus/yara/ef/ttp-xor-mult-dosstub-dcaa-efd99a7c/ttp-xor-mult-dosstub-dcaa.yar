rule TTP_XOR_MULT_DOSStub_dcaa {
  strings:
    $key_dcaa = { 88 c2 [2] fc da [2] bb d8 [2] fc c9 [2] b2 c5 [2] be cf [2] a9 c4 [2] b2 8a [2] 8f }

  condition:
    any of them
}