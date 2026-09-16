rule TTP_XOR_MULT_DOSStub_e307 {
  strings:
    $key_e307 = { b7 6f [2] c3 77 [2] 84 75 [2] c3 64 [2] 8d 68 [2] 81 62 [2] 96 69 [2] 8d 27 [2] b0 }

  condition:
    any of them
}