rule TTP_XOR_MULT_DOSStub_5af3 {
  strings:
    $key_5af3 = { 0e 9b [2] 7a 83 [2] 3d 81 [2] 7a 90 [2] 34 9c [2] 38 96 [2] 2f 9d [2] 34 d3 [2] 09 }

  condition:
    any of them
}