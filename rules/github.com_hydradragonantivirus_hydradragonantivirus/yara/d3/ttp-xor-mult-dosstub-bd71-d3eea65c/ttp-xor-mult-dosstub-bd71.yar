rule TTP_XOR_MULT_DOSStub_bd71 {
  strings:
    $key_bd71 = { e9 19 [2] 9d 01 [2] da 03 [2] 9d 12 [2] d3 1e [2] df 14 [2] c8 1f [2] d3 51 [2] ee }

  condition:
    any of them
}