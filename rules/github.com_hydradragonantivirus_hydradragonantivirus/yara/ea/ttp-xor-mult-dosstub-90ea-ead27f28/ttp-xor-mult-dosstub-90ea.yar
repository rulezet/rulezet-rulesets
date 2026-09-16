rule TTP_XOR_MULT_DOSStub_90ea {
  strings:
    $key_90ea = { c4 82 [2] b0 9a [2] f7 98 [2] b0 89 [2] fe 85 [2] f2 8f [2] e5 84 [2] fe ca [2] c3 }

  condition:
    any of them
}