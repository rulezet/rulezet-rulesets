rule TTP_XOR_MULT_DOSStub_27f3 {
  strings:
    $key_27f3 = { 73 9b [2] 07 83 [2] 40 81 [2] 07 90 [2] 49 9c [2] 45 96 [2] 52 9d [2] 49 d3 [2] 74 }

  condition:
    any of them
}