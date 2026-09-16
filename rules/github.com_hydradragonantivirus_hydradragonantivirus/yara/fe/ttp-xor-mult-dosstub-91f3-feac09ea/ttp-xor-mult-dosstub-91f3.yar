rule TTP_XOR_MULT_DOSStub_91f3 {
  strings:
    $key_91f3 = { c5 9b [2] b1 83 [2] f6 81 [2] b1 90 [2] ff 9c [2] f3 96 [2] e4 9d [2] ff d3 [2] c2 }

  condition:
    any of them
}