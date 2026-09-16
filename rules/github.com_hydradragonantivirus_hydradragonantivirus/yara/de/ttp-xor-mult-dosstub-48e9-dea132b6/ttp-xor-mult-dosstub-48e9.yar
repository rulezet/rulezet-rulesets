rule TTP_XOR_MULT_DOSStub_48e9 {
  strings:
    $key_48e9 = { 1c 81 [2] 68 99 [2] 2f 9b [2] 68 8a [2] 26 86 [2] 2a 8c [2] 3d 87 [2] 26 c9 [2] 1b }

  condition:
    any of them
}