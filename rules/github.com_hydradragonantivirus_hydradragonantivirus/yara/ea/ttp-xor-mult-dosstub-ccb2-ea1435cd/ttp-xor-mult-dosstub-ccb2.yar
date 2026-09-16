rule TTP_XOR_MULT_DOSStub_ccb2 {
  strings:
    $key_ccb2 = { 98 da [2] ec c2 [2] ab c0 [2] ec d1 [2] a2 dd [2] ae d7 [2] b9 dc [2] a2 92 [2] 9f }

  condition:
    any of them
}