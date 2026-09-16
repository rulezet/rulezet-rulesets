rule TTP_XOR_MULT_DOSStub_61d0 {
  strings:
    $key_61d0 = { 35 b8 [2] 41 a0 [2] 06 a2 [2] 41 b3 [2] 0f bf [2] 03 b5 [2] 14 be [2] 0f f0 [2] 32 }

  condition:
    any of them
}