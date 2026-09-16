rule TTP_XOR_MULT_DOSStub_abde {
  strings:
    $key_abde = { ff b6 [2] 8b ae [2] cc ac [2] 8b bd [2] c5 b1 [2] c9 bb [2] de b0 [2] c5 fe [2] f8 }

  condition:
    any of them
}