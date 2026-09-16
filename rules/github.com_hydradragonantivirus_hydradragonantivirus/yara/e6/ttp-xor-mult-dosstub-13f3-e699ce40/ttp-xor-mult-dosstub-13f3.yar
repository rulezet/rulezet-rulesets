rule TTP_XOR_MULT_DOSStub_13f3 {
  strings:
    $key_13f3 = { 47 9b [2] 33 83 [2] 74 81 [2] 33 90 [2] 7d 9c [2] 71 96 [2] 66 9d [2] 7d d3 [2] 40 }

  condition:
    any of them
}