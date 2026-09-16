rule TTP_XOR_MULT_DOSStub_4ecc {
  strings:
    $key_4ecc = { 1a a4 [2] 6e bc [2] 29 be [2] 6e af [2] 20 a3 [2] 2c a9 [2] 3b a2 [2] 20 ec [2] 1d }

  condition:
    any of them
}