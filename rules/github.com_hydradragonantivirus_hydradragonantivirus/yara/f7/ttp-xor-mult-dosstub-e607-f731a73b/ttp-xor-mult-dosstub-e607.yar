rule TTP_XOR_MULT_DOSStub_e607 {
  strings:
    $key_e607 = { b2 6f [2] c6 77 [2] 81 75 [2] c6 64 [2] 88 68 [2] 84 62 [2] 93 69 [2] 88 27 [2] b5 }

  condition:
    any of them
}