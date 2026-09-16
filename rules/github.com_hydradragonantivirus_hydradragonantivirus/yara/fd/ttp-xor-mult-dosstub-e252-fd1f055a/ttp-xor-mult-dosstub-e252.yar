rule TTP_XOR_MULT_DOSStub_e252 {
  strings:
    $key_e252 = { b6 3a [2] c2 22 [2] 85 20 [2] c2 31 [2] 8c 3d [2] 80 37 [2] 97 3c [2] 8c 72 [2] b1 }

  condition:
    any of them
}