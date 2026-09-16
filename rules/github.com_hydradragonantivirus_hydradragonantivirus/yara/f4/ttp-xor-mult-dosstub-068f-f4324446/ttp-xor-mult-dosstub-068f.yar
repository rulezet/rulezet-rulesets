rule TTP_XOR_MULT_DOSStub_068f {
  strings:
    $key_068f = { 52 e7 [2] 26 ff [2] 61 fd [2] 26 ec [2] 68 e0 [2] 64 ea [2] 73 e1 [2] 68 af [2] 55 }

  condition:
    any of them
}