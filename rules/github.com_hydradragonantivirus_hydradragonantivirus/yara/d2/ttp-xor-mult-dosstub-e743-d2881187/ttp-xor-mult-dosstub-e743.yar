rule TTP_XOR_MULT_DOSStub_e743 {
  strings:
    $key_e743 = { b3 2b [2] c7 33 [2] 80 31 [2] c7 20 [2] 89 2c [2] 85 26 [2] 92 2d [2] 89 63 [2] b4 }

  condition:
    any of them
}