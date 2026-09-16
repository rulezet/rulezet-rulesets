rule TTP_XOR_MULT_DOSStub_a7ba {
  strings:
    $key_a7ba = { f3 d2 [2] 87 ca [2] c0 c8 [2] 87 d9 [2] c9 d5 [2] c5 df [2] d2 d4 [2] c9 9a [2] f4 }

  condition:
    any of them
}