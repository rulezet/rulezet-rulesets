rule TTP_XOR_MULT_DOSStub_e18c {
  strings:
    $key_e18c = { b5 e4 [2] c1 fc [2] 86 fe [2] c1 ef [2] 8f e3 [2] 83 e9 [2] 94 e2 [2] 8f ac [2] b2 }

  condition:
    any of them
}