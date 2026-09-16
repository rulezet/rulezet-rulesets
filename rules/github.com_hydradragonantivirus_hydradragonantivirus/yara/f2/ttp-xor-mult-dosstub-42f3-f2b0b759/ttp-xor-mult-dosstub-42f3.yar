rule TTP_XOR_MULT_DOSStub_42f3 {
  strings:
    $key_42f3 = { 16 9b [2] 62 83 [2] 25 81 [2] 62 90 [2] 2c 9c [2] 20 96 [2] 37 9d [2] 2c d3 [2] 11 }

  condition:
    any of them
}