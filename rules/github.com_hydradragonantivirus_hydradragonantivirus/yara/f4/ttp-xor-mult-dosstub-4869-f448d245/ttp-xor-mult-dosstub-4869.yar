rule TTP_XOR_MULT_DOSStub_4869 {
  strings:
    $key_4869 = { 1c 01 [2] 68 19 [2] 2f 1b [2] 68 0a [2] 26 06 [2] 2a 0c [2] 3d 07 [2] 26 49 [2] 1b }

  condition:
    any of them
}