rule TTP_XOR_MULT_DOSStub_bd06 {
  strings:
    $key_bd06 = { e9 6e [2] 9d 76 [2] da 74 [2] 9d 65 [2] d3 69 [2] df 63 [2] c8 68 [2] d3 26 [2] ee }

  condition:
    any of them
}