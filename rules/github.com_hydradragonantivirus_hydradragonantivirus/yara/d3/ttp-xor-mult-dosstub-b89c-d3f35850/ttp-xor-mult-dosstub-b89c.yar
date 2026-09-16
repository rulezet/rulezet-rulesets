rule TTP_XOR_MULT_DOSStub_b89c {
  strings:
    $key_b89c = { ec f4 [2] 98 ec [2] df ee [2] 98 ff [2] d6 f3 [2] da f9 [2] cd f2 [2] d6 bc [2] eb }

  condition:
    any of them
}