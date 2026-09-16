rule TTP_XOR_MULT_DOSStub_2458 {
  strings:
    $key_2458 = { 70 30 [2] 04 28 [2] 43 2a [2] 04 3b [2] 4a 37 [2] 46 3d [2] 51 36 [2] 4a 78 [2] 77 }

  condition:
    any of them
}