rule TTP_XOR_MULT_DOSStub_e552 {
  strings:
    $key_e552 = { b1 3a [2] c5 22 [2] 82 20 [2] c5 31 [2] 8b 3d [2] 87 37 [2] 90 3c [2] 8b 72 [2] b6 }

  condition:
    any of them
}