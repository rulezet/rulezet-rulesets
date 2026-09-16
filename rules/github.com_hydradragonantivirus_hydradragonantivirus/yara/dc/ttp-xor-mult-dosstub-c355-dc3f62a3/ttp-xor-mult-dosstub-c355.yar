rule TTP_XOR_MULT_DOSStub_c355 {
  strings:
    $key_c355 = { 97 3d [2] e3 25 [2] a4 27 [2] e3 36 [2] ad 3a [2] a1 30 [2] b6 3b [2] ad 75 [2] 90 }

  condition:
    any of them
}