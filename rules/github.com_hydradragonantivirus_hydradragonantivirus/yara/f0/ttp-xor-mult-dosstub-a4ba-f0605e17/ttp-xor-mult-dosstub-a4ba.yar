rule TTP_XOR_MULT_DOSStub_a4ba {
  strings:
    $key_a4ba = { f0 d2 [2] 84 ca [2] c3 c8 [2] 84 d9 [2] ca d5 [2] c6 df [2] d1 d4 [2] ca 9a [2] f7 }

  condition:
    any of them
}