rule TTP_XOR_MULT_DOSStub_6ade {
  strings:
    $key_6ade = { 3e b6 [2] 4a ae [2] 0d ac [2] 4a bd [2] 04 b1 [2] 08 bb [2] 1f b0 [2] 04 fe [2] 39 }

  condition:
    any of them
}