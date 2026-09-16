rule TTP_XOR_MULT_DOSStub_61e6 {
  strings:
    $key_61e6 = { 35 8e [2] 41 96 [2] 06 94 [2] 41 85 [2] 0f 89 [2] 03 83 [2] 14 88 [2] 0f c6 [2] 32 }

  condition:
    any of them
}