rule TTP_XOR_QUAD_CurrentVersionRun_a42e {
  strings:
    $key_a42e = { f7 41 [2] d3 4f [2] f8 63 [2] d6 41 [2] c2 5a [2] cd 40 [2] d3 5d [2] d1 5c [2] ca 5a [2] d6 5d [2] ca 72 }

  condition:
    any of them
}