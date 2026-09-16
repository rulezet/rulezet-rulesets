rule TTP_XOR_MULT_DOSStub_731f {
  strings:
    $key_731f = { 27 77 [2] 53 6f [2] 14 6d [2] 53 7c [2] 1d 70 [2] 11 7a [2] 06 71 [2] 1d 3f [2] 20 }

  condition:
    any of them
}