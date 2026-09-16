rule TTP_XOR_MULT_DOSStub_bd76 {
  strings:
    $key_bd76 = { e9 1e [2] 9d 06 [2] da 04 [2] 9d 15 [2] d3 19 [2] df 13 [2] c8 18 [2] d3 56 [2] ee }

  condition:
    any of them
}