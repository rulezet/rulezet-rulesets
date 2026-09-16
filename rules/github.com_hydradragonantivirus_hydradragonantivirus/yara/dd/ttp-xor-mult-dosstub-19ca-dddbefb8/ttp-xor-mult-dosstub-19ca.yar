rule TTP_XOR_MULT_DOSStub_19ca {
  strings:
    $key_19ca = { 4d a2 [2] 39 ba [2] 7e b8 [2] 39 a9 [2] 77 a5 [2] 7b af [2] 6c a4 [2] 77 ea [2] 4a }

  condition:
    any of them
}