rule TTP_XOR_MULT_DOSStub_bd47 {
  strings:
    $key_bd47 = { e9 2f [2] 9d 37 [2] da 35 [2] 9d 24 [2] d3 28 [2] df 22 [2] c8 29 [2] d3 67 [2] ee }

  condition:
    any of them
}