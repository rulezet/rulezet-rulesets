rule TTP_XOR_MULT_DOSStub_06f3 {
  strings:
    $key_06f3 = { 52 9b [2] 26 83 [2] 61 81 [2] 26 90 [2] 68 9c [2] 64 96 [2] 73 9d [2] 68 d3 [2] 55 }

  condition:
    any of them
}