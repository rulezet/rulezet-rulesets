rule TTP_XOR_MULT_DOSStub_e351 {
  strings:
    $key_e351 = { b7 39 [2] c3 21 [2] 84 23 [2] c3 32 [2] 8d 3e [2] 81 34 [2] 96 3f [2] 8d 71 [2] b0 }

  condition:
    any of them
}