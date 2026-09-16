rule TTP_XOR_MULT_DOSStub_0b52 {
  strings:
    $key_0b52 = { 5f 3a [2] 2b 22 [2] 6c 20 [2] 2b 31 [2] 65 3d [2] 69 37 [2] 7e 3c [2] 65 72 [2] 58 }

  condition:
    any of them
}