rule TTP_XOR_MULT_DOSStub_1553 {
  strings:
    $key_1553 = { 41 3b [2] 35 23 [2] 72 21 [2] 35 30 [2] 7b 3c [2] 77 36 [2] 60 3d [2] 7b 73 [2] 46 }

  condition:
    any of them
}