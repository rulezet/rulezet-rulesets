rule TTP_XOR_MULT_DOSStub_4fcc {
  strings:
    $key_4fcc = { 1b a4 [2] 6f bc [2] 28 be [2] 6f af [2] 21 a3 [2] 2d a9 [2] 3a a2 [2] 21 ec [2] 1c }

  condition:
    any of them
}