rule TTP_XOR_MULT_DOSStub_0ff3 {
  strings:
    $key_0ff3 = { 5b 9b [2] 2f 83 [2] 68 81 [2] 2f 90 [2] 61 9c [2] 6d 96 [2] 7a 9d [2] 61 d3 [2] 5c }

  condition:
    any of them
}