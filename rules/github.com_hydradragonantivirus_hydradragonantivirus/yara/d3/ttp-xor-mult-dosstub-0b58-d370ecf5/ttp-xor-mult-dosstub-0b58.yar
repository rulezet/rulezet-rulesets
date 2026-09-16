rule TTP_XOR_MULT_DOSStub_0b58 {
  strings:
    $key_0b58 = { 5f 30 [2] 2b 28 [2] 6c 2a [2] 2b 3b [2] 65 37 [2] 69 3d [2] 7e 36 [2] 65 78 [2] 58 }

  condition:
    any of them
}