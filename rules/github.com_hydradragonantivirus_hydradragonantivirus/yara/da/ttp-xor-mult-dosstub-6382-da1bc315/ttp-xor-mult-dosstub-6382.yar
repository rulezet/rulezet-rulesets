rule TTP_XOR_MULT_DOSStub_6382 {
  strings:
    $key_6382 = { 37 ea [2] 43 f2 [2] 04 f0 [2] 43 e1 [2] 0d ed [2] 01 e7 [2] 16 ec [2] 0d a2 [2] 30 }

  condition:
    any of them
}