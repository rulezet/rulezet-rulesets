rule TTP_XOR_MULT_DOSStub_5882 {
  strings:
    $key_5882 = { 0c ea [2] 78 f2 [2] 3f f0 [2] 78 e1 [2] 36 ed [2] 3a e7 [2] 2d ec [2] 36 a2 [2] 0b }

  condition:
    any of them
}