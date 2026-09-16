rule TTP_XOR_MULT_DOSStub_71e7 {
  strings:
    $key_71e7 = { 25 8f [2] 51 97 [2] 16 95 [2] 51 84 [2] 1f 88 [2] 13 82 [2] 04 89 [2] 1f c7 [2] 22 }

  condition:
    any of them
}