rule TTP_XOR_MULT_DOSStub_298d {
  strings:
    $key_298d = { 7d e5 [2] 09 fd [2] 4e ff [2] 09 ee [2] 47 e2 [2] 4b e8 [2] 5c e3 [2] 47 ad [2] 7a }

  condition:
    any of them
}