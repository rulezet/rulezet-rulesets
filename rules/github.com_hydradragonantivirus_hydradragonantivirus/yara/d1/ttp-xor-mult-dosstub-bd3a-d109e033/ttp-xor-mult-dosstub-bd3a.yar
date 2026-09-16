rule TTP_XOR_MULT_DOSStub_bd3a {
  strings:
    $key_bd3a = { e9 52 [2] 9d 4a [2] da 48 [2] 9d 59 [2] d3 55 [2] df 5f [2] c8 54 [2] d3 1a [2] ee }

  condition:
    any of them
}