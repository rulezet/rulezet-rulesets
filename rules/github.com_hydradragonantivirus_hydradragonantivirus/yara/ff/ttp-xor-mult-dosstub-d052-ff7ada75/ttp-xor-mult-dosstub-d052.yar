rule TTP_XOR_MULT_DOSStub_d052 {
  strings:
    $key_d052 = { 84 3a [2] f0 22 [2] b7 20 [2] f0 31 [2] be 3d [2] b2 37 [2] a5 3c [2] be 72 [2] 83 }

  condition:
    any of them
}