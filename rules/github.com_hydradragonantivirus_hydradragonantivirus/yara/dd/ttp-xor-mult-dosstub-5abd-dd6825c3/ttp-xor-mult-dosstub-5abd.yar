rule TTP_XOR_MULT_DOSStub_5abd {
  strings:
    $key_5abd = { 0e d5 [2] 7a cd [2] 3d cf [2] 7a de [2] 34 d2 [2] 38 d8 [2] 2f d3 [2] 34 9d [2] 09 }

  condition:
    any of them
}