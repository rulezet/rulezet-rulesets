rule TTP_XOR_MULT_DOSStub_0852 {
  strings:
    $key_0852 = { 5c 3a [2] 28 22 [2] 6f 20 [2] 28 31 [2] 66 3d [2] 6a 37 [2] 7d 3c [2] 66 72 [2] 5b }

  condition:
    any of them
}