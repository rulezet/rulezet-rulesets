rule TTP_XOR_MULT_DOSStub_12f3 {
  strings:
    $key_12f3 = { 46 9b [2] 32 83 [2] 75 81 [2] 32 90 [2] 7c 9c [2] 70 96 [2] 67 9d [2] 7c d3 [2] 41 }

  condition:
    any of them
}