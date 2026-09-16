rule TTP_XOR_MULT_DOSStub_6bde {
  strings:
    $key_6bde = { 3f b6 [2] 4b ae [2] 0c ac [2] 4b bd [2] 05 b1 [2] 09 bb [2] 1e b0 [2] 05 fe [2] 38 }

  condition:
    any of them
}