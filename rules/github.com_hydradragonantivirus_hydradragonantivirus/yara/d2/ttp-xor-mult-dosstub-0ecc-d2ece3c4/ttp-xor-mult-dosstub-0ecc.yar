rule TTP_XOR_MULT_DOSStub_0ecc {
  strings:
    $key_0ecc = { 5a a4 [2] 2e bc [2] 69 be [2] 2e af [2] 60 a3 [2] 6c a9 [2] 7b a2 [2] 60 ec [2] 5d }

  condition:
    any of them
}