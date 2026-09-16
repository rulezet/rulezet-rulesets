rule TTP_XOR_MULT_DOSStub_1752 {
  strings:
    $key_1752 = { 43 3a [2] 37 22 [2] 70 20 [2] 37 31 [2] 79 3d [2] 75 37 [2] 62 3c [2] 79 72 [2] 44 }

  condition:
    any of them
}