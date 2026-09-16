rule TTP_XOR_MULT_DOSStub_1ecc {
  strings:
    $key_1ecc = { 4a a4 [2] 3e bc [2] 79 be [2] 3e af [2] 70 a3 [2] 7c a9 [2] 6b a2 [2] 70 ec [2] 4d }

  condition:
    any of them
}