rule TTP_XOR_MULT_DOSStub_bd36 {
  strings:
    $key_bd36 = { e9 5e [2] 9d 46 [2] da 44 [2] 9d 55 [2] d3 59 [2] df 53 [2] c8 58 [2] d3 16 [2] ee }

  condition:
    any of them
}