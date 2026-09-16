rule TTP_XOR_MULT_DOSStub_5782 {
  strings:
    $key_5782 = { 03 ea [2] 77 f2 [2] 30 f0 [2] 77 e1 [2] 39 ed [2] 35 e7 [2] 22 ec [2] 39 a2 [2] 04 }

  condition:
    any of them
}