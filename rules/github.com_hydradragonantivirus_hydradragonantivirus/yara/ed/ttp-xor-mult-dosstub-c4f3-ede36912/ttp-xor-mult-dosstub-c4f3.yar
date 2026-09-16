rule TTP_XOR_MULT_DOSStub_c4f3 {
  strings:
    $key_c4f3 = { 90 9b [2] e4 83 [2] a3 81 [2] e4 90 [2] aa 9c [2] a6 96 [2] b1 9d [2] aa d3 [2] 97 }

  condition:
    any of them
}