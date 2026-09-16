rule TTP_XOR_MULT_DOSStub_ceaf {
  strings:
    $key_ceaf = { 9a c7 [2] ee df [2] a9 dd [2] ee cc [2] a0 c0 [2] ac ca [2] bb c1 [2] a0 8f [2] 9d }

  condition:
    any of them
}