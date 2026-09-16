rule TTP_XOR_MULT_DOSStub_e75d {
  strings:
    $key_e75d = { b3 35 [2] c7 2d [2] 80 2f [2] c7 3e [2] 89 32 [2] 85 38 [2] 92 33 [2] 89 7d [2] b4 }

  condition:
    any of them
}