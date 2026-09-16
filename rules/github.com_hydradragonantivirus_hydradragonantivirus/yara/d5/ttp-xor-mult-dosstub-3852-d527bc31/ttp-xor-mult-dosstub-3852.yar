rule TTP_XOR_MULT_DOSStub_3852 {
  strings:
    $key_3852 = { 6c 3a [2] 18 22 [2] 5f 20 [2] 18 31 [2] 56 3d [2] 5a 37 [2] 4d 3c [2] 56 72 [2] 6b }

  condition:
    any of them
}