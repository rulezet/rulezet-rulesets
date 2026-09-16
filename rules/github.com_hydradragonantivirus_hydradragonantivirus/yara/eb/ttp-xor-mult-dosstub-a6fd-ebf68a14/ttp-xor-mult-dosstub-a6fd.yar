rule TTP_XOR_MULT_DOSStub_a6fd {
  strings:
    $key_a6fd = { f2 95 [2] 86 8d [2] c1 8f [2] 86 9e [2] c8 92 [2] c4 98 [2] d3 93 [2] c8 dd [2] f5 }

  condition:
    any of them
}