rule TTP_XOR_MULT_DOSStub_6985 {
  strings:
    $key_6985 = { 3d ed [2] 49 f5 [2] 0e f7 [2] 49 e6 [2] 07 ea [2] 0b e0 [2] 1c eb [2] 07 a5 [2] 3a }

  condition:
    any of them
}