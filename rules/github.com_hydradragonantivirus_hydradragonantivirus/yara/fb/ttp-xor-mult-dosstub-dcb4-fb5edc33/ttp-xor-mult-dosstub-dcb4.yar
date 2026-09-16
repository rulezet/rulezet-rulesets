rule TTP_XOR_MULT_DOSStub_dcb4 {
  strings:
    $key_dcb4 = { 88 dc [2] fc c4 [2] bb c6 [2] fc d7 [2] b2 db [2] be d1 [2] a9 da [2] b2 94 [2] 8f }

  condition:
    any of them
}