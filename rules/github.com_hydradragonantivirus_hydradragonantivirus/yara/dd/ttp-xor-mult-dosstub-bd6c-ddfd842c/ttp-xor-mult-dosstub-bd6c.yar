rule TTP_XOR_MULT_DOSStub_bd6c {
  strings:
    $key_bd6c = { e9 04 [2] 9d 1c [2] da 1e [2] 9d 0f [2] d3 03 [2] df 09 [2] c8 02 [2] d3 4c [2] ee }

  condition:
    any of them
}