rule TTP_XOR_MULT_DOSStub_48e8 {
  strings:
    $key_48e8 = { 1c 80 [2] 68 98 [2] 2f 9a [2] 68 8b [2] 26 87 [2] 2a 8d [2] 3d 86 [2] 26 c8 [2] 1b }

  condition:
    any of them
}