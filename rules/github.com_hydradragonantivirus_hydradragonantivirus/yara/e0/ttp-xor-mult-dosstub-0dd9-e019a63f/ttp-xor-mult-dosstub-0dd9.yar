rule TTP_XOR_MULT_DOSStub_0dd9 {
  strings:
    $key_0dd9 = { 59 b1 [2] 2d a9 [2] 6a ab [2] 2d ba [2] 63 b6 [2] 6f bc [2] 78 b7 [2] 63 f9 [2] 5e }

  condition:
    any of them
}