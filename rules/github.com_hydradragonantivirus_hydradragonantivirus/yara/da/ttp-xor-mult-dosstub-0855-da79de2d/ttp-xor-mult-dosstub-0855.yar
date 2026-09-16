rule TTP_XOR_MULT_DOSStub_0855 {
  strings:
    $key_0855 = { 5c 3d [2] 28 25 [2] 6f 27 [2] 28 36 [2] 66 3a [2] 6a 30 [2] 7d 3b [2] 66 75 [2] 5b }

  condition:
    any of them
}