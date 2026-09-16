rule TTP_XOR_MULT_DOSStub_28f3 {
  strings:
    $key_28f3 = { 7c 9b [2] 08 83 [2] 4f 81 [2] 08 90 [2] 46 9c [2] 4a 96 [2] 5d 9d [2] 46 d3 [2] 7b }

  condition:
    any of them
}