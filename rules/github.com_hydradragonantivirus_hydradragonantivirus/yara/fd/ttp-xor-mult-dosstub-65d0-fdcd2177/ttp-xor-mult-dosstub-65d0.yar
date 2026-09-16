rule TTP_XOR_MULT_DOSStub_65d0 {
  strings:
    $key_65d0 = { 31 b8 [2] 45 a0 [2] 02 a2 [2] 45 b3 [2] 0b bf [2] 07 b5 [2] 10 be [2] 0b f0 [2] 36 }

  condition:
    any of them
}