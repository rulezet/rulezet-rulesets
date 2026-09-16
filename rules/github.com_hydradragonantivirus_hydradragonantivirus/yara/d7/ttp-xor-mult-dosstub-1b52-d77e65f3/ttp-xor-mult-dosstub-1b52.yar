rule TTP_XOR_MULT_DOSStub_1b52 {
  strings:
    $key_1b52 = { 4f 3a [2] 3b 22 [2] 7c 20 [2] 3b 31 [2] 75 3d [2] 79 37 [2] 6e 3c [2] 75 72 [2] 48 }

  condition:
    any of them
}