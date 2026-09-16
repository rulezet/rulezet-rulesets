rule TTP_XOR_MULT_DOSStub_bccc {
  strings:
    $key_bccc = { e8 a4 [2] 9c bc [2] db be [2] 9c af [2] d2 a3 [2] de a9 [2] c9 a2 [2] d2 ec [2] ef }

  condition:
    any of them
}