rule TTP_XOR_MULT_DOSStub_6453 {
  strings:
    $key_6453 = { 30 3b [2] 44 23 [2] 03 21 [2] 44 30 [2] 0a 3c [2] 06 36 [2] 11 3d [2] 0a 73 [2] 37 }

  condition:
    any of them
}