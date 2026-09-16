rule TTP_XOR_MULT_DOSStub_bb8f {
  strings:
    $key_bb8f = { ef e7 [2] 9b ff [2] dc fd [2] 9b ec [2] d5 e0 [2] d9 ea [2] ce e1 [2] d5 af [2] e8 }

  condition:
    any of them
}