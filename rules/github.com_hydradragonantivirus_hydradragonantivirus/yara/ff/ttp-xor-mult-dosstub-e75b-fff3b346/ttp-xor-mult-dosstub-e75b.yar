rule TTP_XOR_MULT_DOSStub_e75b {
  strings:
    $key_e75b = { b3 33 [2] c7 2b [2] 80 29 [2] c7 38 [2] 89 34 [2] 85 3e [2] 92 35 [2] 89 7b [2] b4 }

  condition:
    any of them
}