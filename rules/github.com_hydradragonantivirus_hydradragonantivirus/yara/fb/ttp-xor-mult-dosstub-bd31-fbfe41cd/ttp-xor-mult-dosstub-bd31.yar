rule TTP_XOR_MULT_DOSStub_bd31 {
  strings:
    $key_bd31 = { e9 59 [2] 9d 41 [2] da 43 [2] 9d 52 [2] d3 5e [2] df 54 [2] c8 5f [2] d3 11 [2] ee }

  condition:
    any of them
}