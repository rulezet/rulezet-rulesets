rule TTP_XOR_MULT_DOSStub_e7f8 {
  strings:
    $key_e7f8 = { b3 90 [2] c7 88 [2] 80 8a [2] c7 9b [2] 89 97 [2] 85 9d [2] 92 96 [2] 89 d8 [2] b4 }

  condition:
    any of them
}