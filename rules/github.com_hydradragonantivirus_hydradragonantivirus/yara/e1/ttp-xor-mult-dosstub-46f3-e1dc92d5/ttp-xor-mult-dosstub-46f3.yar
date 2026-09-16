rule TTP_XOR_MULT_DOSStub_46f3 {
  strings:
    $key_46f3 = { 12 9b [2] 66 83 [2] 21 81 [2] 66 90 [2] 28 9c [2] 24 96 [2] 33 9d [2] 28 d3 [2] 15 }

  condition:
    any of them
}