rule TTP_XOR_MULT_DOSStub_b48c {
  strings:
    $key_b48c = { e0 e4 [2] 94 fc [2] d3 fe [2] 94 ef [2] da e3 [2] d6 e9 [2] c1 e2 [2] da ac [2] e7 }

  condition:
    any of them
}