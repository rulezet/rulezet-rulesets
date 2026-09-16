rule TTP_XOR_MULT_DOSStub_2755 {
  strings:
    $key_2755 = { 73 3d [2] 07 25 [2] 40 27 [2] 07 36 [2] 49 3a [2] 45 30 [2] 52 3b [2] 49 75 [2] 74 }

  condition:
    any of them
}