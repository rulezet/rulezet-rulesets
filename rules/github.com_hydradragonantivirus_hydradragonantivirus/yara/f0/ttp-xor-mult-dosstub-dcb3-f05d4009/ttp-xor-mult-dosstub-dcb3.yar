rule TTP_XOR_MULT_DOSStub_dcb3 {
  strings:
    $key_dcb3 = { 88 db [2] fc c3 [2] bb c1 [2] fc d0 [2] b2 dc [2] be d6 [2] a9 dd [2] b2 93 [2] 8f }

  condition:
    any of them
}