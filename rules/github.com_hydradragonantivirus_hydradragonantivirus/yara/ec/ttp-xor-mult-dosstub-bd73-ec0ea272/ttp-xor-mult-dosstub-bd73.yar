rule TTP_XOR_MULT_DOSStub_bd73 {
  strings:
    $key_bd73 = { e9 1b [2] 9d 03 [2] da 01 [2] 9d 10 [2] d3 1c [2] df 16 [2] c8 1d [2] d3 53 [2] ee }

  condition:
    any of them
}