rule TTP_XOR_MULT_DOSStub_e6e0 {
  strings:
    $key_e6e0 = { b2 88 [2] c6 90 [2] 81 92 [2] c6 83 [2] 88 8f [2] 84 85 [2] 93 8e [2] 88 c0 [2] b5 }

  condition:
    any of them
}