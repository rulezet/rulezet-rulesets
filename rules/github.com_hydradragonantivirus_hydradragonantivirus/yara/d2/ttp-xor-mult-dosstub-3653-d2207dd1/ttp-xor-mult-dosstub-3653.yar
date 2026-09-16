rule TTP_XOR_MULT_DOSStub_3653 {
  strings:
    $key_3653 = { 62 3b [2] 16 23 [2] 51 21 [2] 16 30 [2] 58 3c [2] 54 36 [2] 43 3d [2] 58 73 [2] 65 }

  condition:
    any of them
}