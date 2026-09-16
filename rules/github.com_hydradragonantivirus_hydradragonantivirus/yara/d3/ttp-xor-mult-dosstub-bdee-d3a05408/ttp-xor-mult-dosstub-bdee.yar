rule TTP_XOR_MULT_DOSStub_bdee {
  strings:
    $key_bdee = { e9 86 [2] 9d 9e [2] da 9c [2] 9d 8d [2] d3 81 [2] df 8b [2] c8 80 [2] d3 ce [2] ee }

  condition:
    any of them
}