rule TTP_XOR_MULT_DOSStub_bd20 {
  strings:
    $key_bd20 = { e9 48 [2] 9d 50 [2] da 52 [2] 9d 43 [2] d3 4f [2] df 45 [2] c8 4e [2] d3 00 [2] ee }

  condition:
    any of them
}