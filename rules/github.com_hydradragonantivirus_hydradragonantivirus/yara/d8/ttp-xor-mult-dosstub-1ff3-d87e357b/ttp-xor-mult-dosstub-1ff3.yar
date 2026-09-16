rule TTP_XOR_MULT_DOSStub_1ff3 {
  strings:
    $key_1ff3 = { 4b 9b [2] 3f 83 [2] 78 81 [2] 3f 90 [2] 71 9c [2] 7d 96 [2] 6a 9d [2] 71 d3 [2] 4c }

  condition:
    any of them
}