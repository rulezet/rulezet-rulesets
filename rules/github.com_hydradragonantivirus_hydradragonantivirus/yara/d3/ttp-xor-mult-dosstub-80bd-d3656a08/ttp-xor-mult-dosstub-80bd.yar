rule TTP_XOR_MULT_DOSStub_80bd {
  strings:
    $key_80bd = { d4 d5 [2] a0 cd [2] e7 cf [2] a0 de [2] ee d2 [2] e2 d8 [2] f5 d3 [2] ee 9d [2] d3 }

  condition:
    any of them
}