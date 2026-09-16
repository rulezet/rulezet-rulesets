rule TTP_XOR_MULT_DOSStub_bdbe {
  strings:
    $key_bdbe = { e9 d6 [2] 9d ce [2] da cc [2] 9d dd [2] d3 d1 [2] df db [2] c8 d0 [2] d3 9e [2] ee }

  condition:
    any of them
}