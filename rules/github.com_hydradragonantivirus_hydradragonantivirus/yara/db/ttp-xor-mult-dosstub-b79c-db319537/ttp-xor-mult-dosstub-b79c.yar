rule TTP_XOR_MULT_DOSStub_b79c {
  strings:
    $key_b79c = { e3 f4 [2] 97 ec [2] d0 ee [2] 97 ff [2] d9 f3 [2] d5 f9 [2] c2 f2 [2] d9 bc [2] e4 }

  condition:
    any of them
}