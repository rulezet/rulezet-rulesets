rule TTP_XOR_MULT_DOSStub_69b5 {
  strings:
    $key_69b5 = { 3d dd [2] 49 c5 [2] 0e c7 [2] 49 d6 [2] 07 da [2] 0b d0 [2] 1c db [2] 07 95 [2] 3a }

  condition:
    any of them
}