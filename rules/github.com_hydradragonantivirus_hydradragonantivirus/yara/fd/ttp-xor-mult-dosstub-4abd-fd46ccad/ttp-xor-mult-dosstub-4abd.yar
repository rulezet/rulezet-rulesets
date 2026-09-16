rule TTP_XOR_MULT_DOSStub_4abd {
  strings:
    $key_4abd = { 1e d5 [2] 6a cd [2] 2d cf [2] 6a de [2] 24 d2 [2] 28 d8 [2] 3f d3 [2] 24 9d [2] 19 }

  condition:
    any of them
}