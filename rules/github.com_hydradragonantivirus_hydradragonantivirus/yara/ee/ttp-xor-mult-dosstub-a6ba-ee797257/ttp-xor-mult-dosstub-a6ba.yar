rule TTP_XOR_MULT_DOSStub_a6ba {
  strings:
    $key_a6ba = { f2 d2 [2] 86 ca [2] c1 c8 [2] 86 d9 [2] c8 d5 [2] c4 df [2] d3 d4 [2] c8 9a [2] f5 }

  condition:
    any of them
}