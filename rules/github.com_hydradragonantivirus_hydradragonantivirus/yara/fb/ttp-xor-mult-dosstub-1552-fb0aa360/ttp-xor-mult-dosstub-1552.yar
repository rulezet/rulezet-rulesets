rule TTP_XOR_MULT_DOSStub_1552 {
  strings:
    $key_1552 = { 41 3a [2] 35 22 [2] 72 20 [2] 35 31 [2] 7b 3d [2] 77 37 [2] 60 3c [2] 7b 72 [2] 46 }

  condition:
    any of them
}