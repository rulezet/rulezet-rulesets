rule TTP_XOR_QUAD_CurrentVersionRun_ab7c {
  strings:
    $key_ab7c = { f8 13 [2] dc 1d [2] f7 31 [2] d9 13 [2] cd 08 [2] c2 12 [2] dc 0f [2] de 0e [2] c5 08 [2] d9 0f [2] c5 20 }

  condition:
    any of them
}