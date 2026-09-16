rule TTP_XOR_MULT_DOSStub_e7e6 {
  strings:
    $key_e7e6 = { b3 8e [2] c7 96 [2] 80 94 [2] c7 85 [2] 89 89 [2] 85 83 [2] 92 88 [2] 89 c6 [2] b4 }

  condition:
    any of them
}