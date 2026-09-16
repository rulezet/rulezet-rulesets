rule TTP_XOR_MULT_DOSStub_438f {
  strings:
    $key_438f = { 17 e7 [2] 63 ff [2] 24 fd [2] 63 ec [2] 2d e0 [2] 21 ea [2] 36 e1 [2] 2d af [2] 10 }

  condition:
    any of them
}