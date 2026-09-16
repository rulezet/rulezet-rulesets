rule TTP_XOR_MULT_DOSStub_e317 {
  strings:
    $key_e317 = { b7 7f [2] c3 67 [2] 84 65 [2] c3 74 [2] 8d 78 [2] 81 72 [2] 96 79 [2] 8d 37 [2] b0 }

  condition:
    any of them
}