rule TTP_XOR_MULT_DOSStub_41e1 {
  strings:
    $key_41e1 = { 15 89 [2] 61 91 [2] 26 93 [2] 61 82 [2] 2f 8e [2] 23 84 [2] 34 8f [2] 2f c1 [2] 12 }

  condition:
    any of them
}