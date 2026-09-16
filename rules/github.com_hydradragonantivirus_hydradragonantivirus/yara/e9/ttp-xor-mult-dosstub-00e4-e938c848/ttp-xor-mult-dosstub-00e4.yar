rule TTP_XOR_MULT_DOSStub_00e4 {
  strings:
    $key_00e4 = { 54 8c [2] 20 94 [2] 67 96 [2] 20 87 [2] 6e 8b [2] 62 81 [2] 75 8a [2] 6e c4 [2] 53 }

  condition:
    any of them
}