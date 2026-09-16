rule TTP_XOR_MULT_DOSStub_e778 {
  strings:
    $key_e778 = { b3 10 [2] c7 08 [2] 80 0a [2] c7 1b [2] 89 17 [2] 85 1d [2] 92 16 [2] 89 58 [2] b4 }

  condition:
    any of them
}