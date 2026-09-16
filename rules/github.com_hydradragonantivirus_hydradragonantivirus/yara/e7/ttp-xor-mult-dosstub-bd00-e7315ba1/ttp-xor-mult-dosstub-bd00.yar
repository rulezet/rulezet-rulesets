rule TTP_XOR_MULT_DOSStub_bd00 {
  strings:
    $key_bd00 = { e9 68 [2] 9d 70 [2] da 72 [2] 9d 63 [2] d3 6f [2] df 65 [2] c8 6e [2] d3 20 [2] ee }

  condition:
    any of them
}