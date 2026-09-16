rule TTP_XOR_QUAD_CurrentVersionRun_ab01 {
  strings:
    $key_ab01 = { f8 6e [2] dc 60 [2] f7 4c [2] d9 6e [2] cd 75 [2] c2 6f [2] dc 72 [2] de 73 [2] c5 75 [2] d9 72 [2] c5 5d }

  condition:
    any of them
}