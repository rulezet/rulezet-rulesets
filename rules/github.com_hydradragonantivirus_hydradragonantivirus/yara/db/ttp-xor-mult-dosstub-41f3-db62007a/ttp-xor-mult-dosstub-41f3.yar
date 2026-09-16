rule TTP_XOR_MULT_DOSStub_41f3 {
  strings:
    $key_41f3 = { 15 9b [2] 61 83 [2] 26 81 [2] 61 90 [2] 2f 9c [2] 23 96 [2] 34 9d [2] 2f d3 [2] 12 }

  condition:
    any of them
}