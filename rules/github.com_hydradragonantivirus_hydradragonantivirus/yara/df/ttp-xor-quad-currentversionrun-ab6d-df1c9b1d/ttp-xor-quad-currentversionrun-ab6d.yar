rule TTP_XOR_QUAD_CurrentVersionRun_ab6d {
  strings:
    $key_ab6d = { f8 02 [2] dc 0c [2] f7 20 [2] d9 02 [2] cd 19 [2] c2 03 [2] dc 1e [2] de 1f [2] c5 19 [2] d9 1e [2] c5 31 }

  condition:
    any of them
}