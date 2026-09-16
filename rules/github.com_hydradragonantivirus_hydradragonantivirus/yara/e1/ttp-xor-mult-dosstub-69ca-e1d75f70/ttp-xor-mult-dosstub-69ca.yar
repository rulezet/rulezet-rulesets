rule TTP_XOR_MULT_DOSStub_69ca {
  strings:
    $key_69ca = { 3d a2 [2] 49 ba [2] 0e b8 [2] 49 a9 [2] 07 a5 [2] 0b af [2] 1c a4 [2] 07 ea [2] 3a }

  condition:
    any of them
}