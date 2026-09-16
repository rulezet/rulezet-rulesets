rule TTP_XOR_MULT_DOSStub_bdff {
  strings:
    $key_bdff = { e9 97 [2] 9d 8f [2] da 8d [2] 9d 9c [2] d3 90 [2] df 9a [2] c8 91 [2] d3 df [2] ee }

  condition:
    any of them
}