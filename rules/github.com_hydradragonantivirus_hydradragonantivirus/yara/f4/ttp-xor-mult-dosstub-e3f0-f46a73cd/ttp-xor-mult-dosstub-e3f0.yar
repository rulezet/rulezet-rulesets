rule TTP_XOR_MULT_DOSStub_e3f0 {
  strings:
    $key_e3f0 = { b7 98 [2] c3 80 [2] 84 82 [2] c3 93 [2] 8d 9f [2] 81 95 [2] 96 9e [2] 8d d0 [2] b0 }

  condition:
    any of them
}