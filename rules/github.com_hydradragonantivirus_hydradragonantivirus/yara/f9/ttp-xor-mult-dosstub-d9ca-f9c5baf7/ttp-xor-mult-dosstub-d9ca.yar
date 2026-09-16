rule TTP_XOR_MULT_DOSStub_d9ca {
  strings:
    $key_d9ca = { 8d a2 [2] f9 ba [2] be b8 [2] f9 a9 [2] b7 a5 [2] bb af [2] ac a4 [2] b7 ea [2] 8a }

  condition:
    any of them
}