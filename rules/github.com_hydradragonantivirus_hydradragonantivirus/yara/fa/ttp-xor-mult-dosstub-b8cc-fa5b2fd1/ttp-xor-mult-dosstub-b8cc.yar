rule TTP_XOR_MULT_DOSStub_b8cc {
  strings:
    $key_b8cc = { ec a4 [2] 98 bc [2] df be [2] 98 af [2] d6 a3 [2] da a9 [2] cd a2 [2] d6 ec [2] eb }

  condition:
    any of them
}