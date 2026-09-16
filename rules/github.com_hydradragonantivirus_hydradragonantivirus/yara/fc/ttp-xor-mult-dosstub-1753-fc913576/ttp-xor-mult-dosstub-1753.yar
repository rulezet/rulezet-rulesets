rule TTP_XOR_MULT_DOSStub_1753 {
  strings:
    $key_1753 = { 43 3b [2] 37 23 [2] 70 21 [2] 37 30 [2] 79 3c [2] 75 36 [2] 62 3d [2] 79 73 [2] 44 }

  condition:
    any of them
}