rule TTP_XOR_QUAD_CurrentVersionRun_ab1e {
  strings:
    $key_ab1e = { f8 71 [2] dc 7f [2] f7 53 [2] d9 71 [2] cd 6a [2] c2 70 [2] dc 6d [2] de 6c [2] c5 6a [2] d9 6d [2] c5 42 }

  condition:
    any of them
}