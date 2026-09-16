rule TTP_XOR_MULT_DOSStub_bd3c {
  strings:
    $key_bd3c = { e9 54 [2] 9d 4c [2] da 4e [2] 9d 5f [2] d3 53 [2] df 59 [2] c8 52 [2] d3 1c [2] ee }

  condition:
    any of them
}