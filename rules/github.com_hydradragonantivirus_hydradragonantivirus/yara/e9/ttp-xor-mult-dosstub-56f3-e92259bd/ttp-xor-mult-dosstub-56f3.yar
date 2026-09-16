rule TTP_XOR_MULT_DOSStub_56f3 {
  strings:
    $key_56f3 = { 02 9b [2] 76 83 [2] 31 81 [2] 76 90 [2] 38 9c [2] 34 96 [2] 23 9d [2] 38 d3 [2] 05 }

  condition:
    any of them
}