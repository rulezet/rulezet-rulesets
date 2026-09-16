rule TTP_XOR_MULT_DOSStub_71e1 {
  strings:
    $key_71e1 = { 25 89 [2] 51 91 [2] 16 93 [2] 51 82 [2] 1f 8e [2] 13 84 [2] 04 8f [2] 1f c1 [2] 22 }

  condition:
    any of them
}