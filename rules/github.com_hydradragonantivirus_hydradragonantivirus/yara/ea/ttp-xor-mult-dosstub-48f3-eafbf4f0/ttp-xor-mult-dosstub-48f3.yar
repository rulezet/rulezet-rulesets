rule TTP_XOR_MULT_DOSStub_48f3 {
  strings:
    $key_48f3 = { 1c 9b [2] 68 83 [2] 2f 81 [2] 68 90 [2] 26 9c [2] 2a 96 [2] 3d 9d [2] 26 d3 [2] 1b }

  condition:
    any of them
}