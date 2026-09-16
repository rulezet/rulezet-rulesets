rule TTP_XOR_MULT_DOSStub_6558 {
  strings:
    $key_6558 = { 31 30 [2] 45 28 [2] 02 2a [2] 45 3b [2] 0b 37 [2] 07 3d [2] 10 36 [2] 0b 78 [2] 36 }

  condition:
    any of them
}