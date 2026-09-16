rule TTP_XOR_MULT_DOSStub_7d9c {
  strings:
    $key_7d9c = { 29 f4 [2] 5d ec [2] 1a ee [2] 5d ff [2] 13 f3 [2] 1f f9 [2] 08 f2 [2] 13 bc [2] 2e }

  condition:
    any of them
}