rule TTP_XOR_MULT_DOSStub_3af3 {
  strings:
    $key_3af3 = { 6e 9b [2] 1a 83 [2] 5d 81 [2] 1a 90 [2] 54 9c [2] 58 96 [2] 4f 9d [2] 54 d3 [2] 69 }

  condition:
    any of them
}