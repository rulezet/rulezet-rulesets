rule TTP_XOR_MULT_DOSStub_b89d {
  strings:
    $key_b89d = { ec f5 [2] 98 ed [2] df ef [2] 98 fe [2] d6 f2 [2] da f8 [2] cd f3 [2] d6 bd [2] eb }

  condition:
    any of them
}