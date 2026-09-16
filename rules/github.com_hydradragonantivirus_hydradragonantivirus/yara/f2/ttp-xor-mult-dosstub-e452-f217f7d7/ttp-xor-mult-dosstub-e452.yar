rule TTP_XOR_MULT_DOSStub_e452 {
  strings:
    $key_e452 = { b0 3a [2] c4 22 [2] 83 20 [2] c4 31 [2] 8a 3d [2] 86 37 [2] 91 3c [2] 8a 72 [2] b7 }

  condition:
    any of them
}