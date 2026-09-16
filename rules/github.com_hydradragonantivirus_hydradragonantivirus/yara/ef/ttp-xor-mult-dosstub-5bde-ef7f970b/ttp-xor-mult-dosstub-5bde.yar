rule TTP_XOR_MULT_DOSStub_5bde {
  strings:
    $key_5bde = { 0f b6 [2] 7b ae [2] 3c ac [2] 7b bd [2] 35 b1 [2] 39 bb [2] 2e b0 [2] 35 fe [2] 08 }

  condition:
    any of them
}