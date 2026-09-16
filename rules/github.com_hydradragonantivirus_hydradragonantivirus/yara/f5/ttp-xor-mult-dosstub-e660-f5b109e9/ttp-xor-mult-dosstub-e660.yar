rule TTP_XOR_MULT_DOSStub_e660 {
  strings:
    $key_e660 = { b2 08 [2] c6 10 [2] 81 12 [2] c6 03 [2] 88 0f [2] 84 05 [2] 93 0e [2] 88 40 [2] b5 }

  condition:
    any of them
}