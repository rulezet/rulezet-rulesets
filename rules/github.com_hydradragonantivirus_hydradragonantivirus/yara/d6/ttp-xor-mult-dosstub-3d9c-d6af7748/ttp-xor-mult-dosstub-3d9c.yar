rule TTP_XOR_MULT_DOSStub_3d9c {
  strings:
    $key_3d9c = { 69 f4 [2] 1d ec [2] 5a ee [2] 1d ff [2] 53 f3 [2] 5f f9 [2] 48 f2 [2] 53 bc [2] 6e }

  condition:
    any of them
}