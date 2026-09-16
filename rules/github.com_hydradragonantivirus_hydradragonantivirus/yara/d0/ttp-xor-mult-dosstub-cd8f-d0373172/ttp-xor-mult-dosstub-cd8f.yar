rule TTP_XOR_MULT_DOSStub_cd8f {
  strings:
    $key_cd8f = { 99 e7 [2] ed ff [2] aa fd [2] ed ec [2] a3 e0 [2] af ea [2] b8 e1 [2] a3 af [2] 9e }

  condition:
    any of them
}