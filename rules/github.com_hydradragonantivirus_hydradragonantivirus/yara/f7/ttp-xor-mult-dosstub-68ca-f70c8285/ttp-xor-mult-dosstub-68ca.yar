rule TTP_XOR_MULT_DOSStub_68ca {
  strings:
    $key_68ca = { 3c a2 [2] 48 ba [2] 0f b8 [2] 48 a9 [2] 06 a5 [2] 0a af [2] 1d a4 [2] 06 ea [2] 3b }

  condition:
    any of them
}