rule TTP_XOR_MULT_DOSStub_1fb1 {
  strings:
    $key_1fb1 = { 4b d9 [2] 3f c1 [2] 78 c3 [2] 3f d2 [2] 71 de [2] 7d d4 [2] 6a df [2] 71 91 [2] 4c }

  condition:
    any of them
}