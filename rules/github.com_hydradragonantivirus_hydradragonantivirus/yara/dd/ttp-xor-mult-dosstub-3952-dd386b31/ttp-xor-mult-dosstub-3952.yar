rule TTP_XOR_MULT_DOSStub_3952 {
  strings:
    $key_3952 = { 6d 3a [2] 19 22 [2] 5e 20 [2] 19 31 [2] 57 3d [2] 5b 37 [2] 4c 3c [2] 57 72 [2] 6a }

  condition:
    any of them
}