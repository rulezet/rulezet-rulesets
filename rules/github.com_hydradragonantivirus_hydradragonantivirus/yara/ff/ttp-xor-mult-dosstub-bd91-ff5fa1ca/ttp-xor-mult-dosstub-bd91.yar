rule TTP_XOR_MULT_DOSStub_bd91 {
  strings:
    $key_bd91 = { e9 f9 [2] 9d e1 [2] da e3 [2] 9d f2 [2] d3 fe [2] df f4 [2] c8 ff [2] d3 b1 [2] ee }

  condition:
    any of them
}