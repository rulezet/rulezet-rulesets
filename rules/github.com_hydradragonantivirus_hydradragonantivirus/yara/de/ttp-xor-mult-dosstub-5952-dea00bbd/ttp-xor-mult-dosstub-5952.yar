rule TTP_XOR_MULT_DOSStub_5952 {
  strings:
    $key_5952 = { 0d 3a [2] 79 22 [2] 3e 20 [2] 79 31 [2] 37 3d [2] 3b 37 [2] 2c 3c [2] 37 72 [2] 0a }

  condition:
    any of them
}