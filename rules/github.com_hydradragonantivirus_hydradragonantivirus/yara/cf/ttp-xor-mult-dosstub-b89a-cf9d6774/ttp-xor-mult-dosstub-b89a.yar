rule TTP_XOR_MULT_DOSStub_b89a {
  strings:
    $key_b89a = { ec f2 [2] 98 ea [2] df e8 [2] 98 f9 [2] d6 f5 [2] da ff [2] cd f4 [2] d6 ba [2] eb }

  condition:
    any of them
}