rule TTP_XOR_MULT_DOSStub_0555 {
  strings:
    $key_0555 = { 51 3d [2] 25 25 [2] 62 27 [2] 25 36 [2] 6b 3a [2] 67 30 [2] 70 3b [2] 6b 75 [2] 56 }

  condition:
    any of them
}