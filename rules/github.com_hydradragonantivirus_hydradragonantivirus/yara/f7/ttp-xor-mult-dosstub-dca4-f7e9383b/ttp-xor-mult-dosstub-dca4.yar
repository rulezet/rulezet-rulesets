rule TTP_XOR_MULT_DOSStub_dca4 {
  strings:
    $key_dca4 = { 88 cc [2] fc d4 [2] bb d6 [2] fc c7 [2] b2 cb [2] be c1 [2] a9 ca [2] b2 84 [2] 8f }

  condition:
    any of them
}