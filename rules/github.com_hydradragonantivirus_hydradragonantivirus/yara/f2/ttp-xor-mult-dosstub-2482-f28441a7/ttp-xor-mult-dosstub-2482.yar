rule TTP_XOR_MULT_DOSStub_2482 {
  strings:
    $key_2482 = { 70 ea [2] 04 f2 [2] 43 f0 [2] 04 e1 [2] 4a ed [2] 46 e7 [2] 51 ec [2] 4a a2 [2] 77 }

  condition:
    any of them
}