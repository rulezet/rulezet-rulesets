rule TTP_XOR_MULT_DOSStub_6abd {
  strings:
    $key_6abd = { 3e d5 [2] 4a cd [2] 0d cf [2] 4a de [2] 04 d2 [2] 08 d8 [2] 1f d3 [2] 04 9d [2] 39 }

  condition:
    any of them
}