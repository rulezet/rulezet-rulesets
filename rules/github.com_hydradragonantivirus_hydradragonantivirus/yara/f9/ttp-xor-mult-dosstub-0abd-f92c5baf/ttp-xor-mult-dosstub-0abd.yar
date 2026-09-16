rule TTP_XOR_MULT_DOSStub_0abd {
  strings:
    $key_0abd = { 5e d5 [2] 2a cd [2] 6d cf [2] 2a de [2] 64 d2 [2] 68 d8 [2] 7f d3 [2] 64 9d [2] 59 }

  condition:
    any of them
}