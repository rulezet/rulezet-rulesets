rule TTP_XOR_MULT_DOSStub_3fcc {
  strings:
    $key_3fcc = { 6b a4 [2] 1f bc [2] 58 be [2] 1f af [2] 51 a3 [2] 5d a9 [2] 4a a2 [2] 51 ec [2] 6c }

  condition:
    any of them
}