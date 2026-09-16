rule TTP_XOR_MULT_DOSStub_6058 {
  strings:
    $key_6058 = { 34 30 [2] 40 28 [2] 07 2a [2] 40 3b [2] 0e 37 [2] 02 3d [2] 15 36 [2] 0e 78 [2] 33 }

  condition:
    any of them
}