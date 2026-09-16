rule TTP_XOR_MULT_DOSStub_e758 {
  strings:
    $key_e758 = { b3 30 [2] c7 28 [2] 80 2a [2] c7 3b [2] 89 37 [2] 85 3d [2] 92 36 [2] 89 78 [2] b4 }

  condition:
    any of them
}