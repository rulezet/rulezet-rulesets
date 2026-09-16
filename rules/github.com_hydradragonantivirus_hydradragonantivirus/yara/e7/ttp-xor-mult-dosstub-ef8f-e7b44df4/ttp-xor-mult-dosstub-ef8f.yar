rule TTP_XOR_MULT_DOSStub_ef8f {
  strings:
    $key_ef8f = { bb e7 [2] cf ff [2] 88 fd [2] cf ec [2] 81 e0 [2] 8d ea [2] 9a e1 [2] 81 af [2] bc }

  condition:
    any of them
}