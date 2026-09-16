rule TTP_XOR_MULT_DOSStub_e765 {
  strings:
    $key_e765 = { b3 0d [2] c7 15 [2] 80 17 [2] c7 06 [2] 89 0a [2] 85 00 [2] 92 0b [2] 89 45 [2] b4 }

  condition:
    any of them
}