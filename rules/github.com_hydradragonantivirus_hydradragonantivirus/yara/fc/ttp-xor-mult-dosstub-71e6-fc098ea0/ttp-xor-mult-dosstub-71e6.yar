rule TTP_XOR_MULT_DOSStub_71e6 {
  strings:
    $key_71e6 = { 25 8e [2] 51 96 [2] 16 94 [2] 51 85 [2] 1f 89 [2] 13 83 [2] 04 88 [2] 1f c6 [2] 22 }

  condition:
    any of them
}