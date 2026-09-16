rule TTP_XOR_MULT_DOSStub_50f3 {
  strings:
    $key_50f3 = { 04 9b [2] 70 83 [2] 37 81 [2] 70 90 [2] 3e 9c [2] 32 96 [2] 25 9d [2] 3e d3 [2] 03 }

  condition:
    any of them
}