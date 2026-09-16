rule TTP_XOR_MULT_DOSStub_29ca {
  strings:
    $key_29ca = { 7d a2 [2] 09 ba [2] 4e b8 [2] 09 a9 [2] 47 a5 [2] 4b af [2] 5c a4 [2] 47 ea [2] 7a }

  condition:
    any of them
}