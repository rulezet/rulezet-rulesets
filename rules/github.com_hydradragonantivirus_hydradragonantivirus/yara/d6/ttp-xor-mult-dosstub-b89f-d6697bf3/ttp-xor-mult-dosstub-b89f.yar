rule TTP_XOR_MULT_DOSStub_b89f {
  strings:
    $key_b89f = { ec f7 [2] 98 ef [2] df ed [2] 98 fc [2] d6 f0 [2] da fa [2] cd f1 [2] d6 bf [2] eb }

  condition:
    any of them
}