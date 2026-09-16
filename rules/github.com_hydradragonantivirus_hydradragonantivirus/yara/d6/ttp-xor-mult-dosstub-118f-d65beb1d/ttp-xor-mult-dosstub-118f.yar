rule TTP_XOR_MULT_DOSStub_118f {
  strings:
    $key_118f = { 45 e7 [2] 31 ff [2] 76 fd [2] 31 ec [2] 7f e0 [2] 73 ea [2] 64 e1 [2] 7f af [2] 42 }

  condition:
    any of them
}