rule TTP_XOR_MULT_DOSStub_37f3 {
  strings:
    $key_37f3 = { 63 9b [2] 17 83 [2] 50 81 [2] 17 90 [2] 59 9c [2] 55 96 [2] 42 9d [2] 59 d3 [2] 64 }

  condition:
    any of them
}