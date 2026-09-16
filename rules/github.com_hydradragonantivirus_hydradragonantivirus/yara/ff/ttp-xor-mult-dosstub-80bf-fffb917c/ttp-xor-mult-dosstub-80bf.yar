rule TTP_XOR_MULT_DOSStub_80bf {
  strings:
    $key_80bf = { d4 d7 [2] a0 cf [2] e7 cd [2] a0 dc [2] ee d0 [2] e2 da [2] f5 d1 [2] ee 9f [2] d3 }

  condition:
    any of them
}