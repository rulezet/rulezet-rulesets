rule TTP_XOR_MULT_DOSStub_b8ca {
  strings:
    $key_b8ca = { ec a2 [2] 98 ba [2] df b8 [2] 98 a9 [2] d6 a5 [2] da af [2] cd a4 [2] d6 ea [2] eb }

  condition:
    any of them
}