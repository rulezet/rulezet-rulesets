rule TTP_XOR_MULT_DOSStub_5708 {
  strings:
    $key_5708 = { 03 60 [2] 77 78 [2] 30 7a [2] 77 6b [2] 39 67 [2] 35 6d [2] 22 66 [2] 39 28 [2] 04 }

  condition:
    any of them
}