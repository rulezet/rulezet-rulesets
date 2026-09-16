rule TTP_XOR_MULT_DOSStub_bd23 {
  strings:
    $key_bd23 = { e9 4b [2] 9d 53 [2] da 51 [2] 9d 40 [2] d3 4c [2] df 46 [2] c8 4d [2] d3 03 [2] ee }

  condition:
    any of them
}