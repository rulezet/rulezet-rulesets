rule TTP_XOR_MULT_DOSStub_bd02 {
  strings:
    $key_bd02 = { e9 6a [2] 9d 72 [2] da 70 [2] 9d 61 [2] d3 6d [2] df 67 [2] c8 6c [2] d3 22 [2] ee }

  condition:
    any of them
}