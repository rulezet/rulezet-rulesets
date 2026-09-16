rule TTP_XOR_MULT_DOSStub_bdf6 {
  strings:
    $key_bdf6 = { e9 9e [2] 9d 86 [2] da 84 [2] 9d 95 [2] d3 99 [2] df 93 [2] c8 98 [2] d3 d6 [2] ee }

  condition:
    any of them
}