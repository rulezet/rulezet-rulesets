rule TTP_XOR_MULT_DOSStub_bd46 {
  strings:
    $key_bd46 = { e9 2e [2] 9d 36 [2] da 34 [2] 9d 25 [2] d3 29 [2] df 23 [2] c8 28 [2] d3 66 [2] ee }

  condition:
    any of them
}