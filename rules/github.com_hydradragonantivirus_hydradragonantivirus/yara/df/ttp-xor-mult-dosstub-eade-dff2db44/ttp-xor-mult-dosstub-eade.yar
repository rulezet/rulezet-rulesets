rule TTP_XOR_MULT_DOSStub_eade {
  strings:
    $key_eade = { be b6 [2] ca ae [2] 8d ac [2] ca bd [2] 84 b1 [2] 88 bb [2] 9f b0 [2] 84 fe [2] b9 }

  condition:
    any of them
}