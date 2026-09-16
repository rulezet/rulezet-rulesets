rule TTP_XOR_MULT_DOSStub_bd13 {
  strings:
    $key_bd13 = { e9 7b [2] 9d 63 [2] da 61 [2] 9d 70 [2] d3 7c [2] df 76 [2] c8 7d [2] d3 33 [2] ee }

  condition:
    any of them
}