rule TTP_XOR_MULT_DOSStub_6553 {
  strings:
    $key_6553 = { 31 3b [2] 45 23 [2] 02 21 [2] 45 30 [2] 0b 3c [2] 07 36 [2] 10 3d [2] 0b 73 [2] 36 }

  condition:
    any of them
}