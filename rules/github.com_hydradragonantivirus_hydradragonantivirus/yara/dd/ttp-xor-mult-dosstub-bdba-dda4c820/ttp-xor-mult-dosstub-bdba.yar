rule TTP_XOR_MULT_DOSStub_bdba {
  strings:
    $key_bdba = { e9 d2 [2] 9d ca [2] da c8 [2] 9d d9 [2] d3 d5 [2] df df [2] c8 d4 [2] d3 9a [2] ee }

  condition:
    any of them
}