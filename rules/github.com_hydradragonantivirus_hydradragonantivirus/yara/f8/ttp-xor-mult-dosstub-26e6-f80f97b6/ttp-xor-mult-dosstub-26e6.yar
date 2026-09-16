rule TTP_XOR_MULT_DOSStub_26e6 {
  strings:
    $key_26e6 = { 72 8e [2] 06 96 [2] 41 94 [2] 06 85 [2] 48 89 [2] 44 83 [2] 53 88 [2] 48 c6 [2] 75 }

  condition:
    any of them
}