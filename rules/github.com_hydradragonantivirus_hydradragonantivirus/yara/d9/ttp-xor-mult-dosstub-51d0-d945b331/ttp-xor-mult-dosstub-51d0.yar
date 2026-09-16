rule TTP_XOR_MULT_DOSStub_51d0 {
  strings:
    $key_51d0 = { 05 b8 [2] 71 a0 [2] 36 a2 [2] 71 b3 [2] 3f bf [2] 33 b5 [2] 24 be [2] 3f f0 [2] 02 }

  condition:
    any of them
}