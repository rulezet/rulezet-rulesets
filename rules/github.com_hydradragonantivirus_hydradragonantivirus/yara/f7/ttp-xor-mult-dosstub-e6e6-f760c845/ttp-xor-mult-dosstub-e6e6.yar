rule TTP_XOR_MULT_DOSStub_e6e6 {
  strings:
    $key_e6e6 = { b2 8e [2] c6 96 [2] 81 94 [2] c6 85 [2] 88 89 [2] 84 83 [2] 93 88 [2] 88 c6 [2] b5 }

  condition:
    any of them
}