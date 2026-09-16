rule TTP_XOR_MULT_DOSStub_0758 {
  strings:
    $key_0758 = { 53 30 [2] 27 28 [2] 60 2a [2] 27 3b [2] 69 37 [2] 65 3d [2] 72 36 [2] 69 78 [2] 54 }

  condition:
    any of them
}