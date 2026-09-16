rule TTP_XOR_MULT_DOSStub_08f3 {
  strings:
    $key_08f3 = { 5c 9b [2] 28 83 [2] 6f 81 [2] 28 90 [2] 66 9c [2] 6a 96 [2] 7d 9d [2] 66 d3 [2] 5b }

  condition:
    any of them
}