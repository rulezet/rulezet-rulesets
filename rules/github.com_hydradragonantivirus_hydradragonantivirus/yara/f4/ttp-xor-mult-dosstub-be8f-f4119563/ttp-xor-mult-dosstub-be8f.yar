rule TTP_XOR_MULT_DOSStub_be8f {
  strings:
    $key_be8f = { ea e7 [2] 9e ff [2] d9 fd [2] 9e ec [2] d0 e0 [2] dc ea [2] cb e1 [2] d0 af [2] ed }

  condition:
    any of them
}