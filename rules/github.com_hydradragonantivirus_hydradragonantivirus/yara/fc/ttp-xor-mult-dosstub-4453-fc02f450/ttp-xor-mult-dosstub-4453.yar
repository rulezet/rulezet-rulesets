rule TTP_XOR_MULT_DOSStub_4453 {
  strings:
    $key_4453 = { 10 3b [2] 64 23 [2] 23 21 [2] 64 30 [2] 2a 3c [2] 26 36 [2] 31 3d [2] 2a 73 [2] 17 }

  condition:
    any of them
}