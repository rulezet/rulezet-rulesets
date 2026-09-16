rule TTP_XOR_MULT_DOSStub_30f3 {
  strings:
    $key_30f3 = { 64 9b [2] 10 83 [2] 57 81 [2] 10 90 [2] 5e 9c [2] 52 96 [2] 45 9d [2] 5e d3 [2] 63 }

  condition:
    any of them
}