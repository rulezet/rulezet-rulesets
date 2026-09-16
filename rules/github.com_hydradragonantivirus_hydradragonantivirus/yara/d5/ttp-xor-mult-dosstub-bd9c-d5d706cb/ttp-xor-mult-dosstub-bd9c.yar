rule TTP_XOR_MULT_DOSStub_bd9c {
  strings:
    $key_bd9c = { e9 f4 [2] 9d ec [2] da ee [2] 9d ff [2] d3 f3 [2] df f9 [2] c8 f2 [2] d3 bc [2] ee }

  condition:
    any of them
}