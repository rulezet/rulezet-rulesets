rule TTP_XOR_QUAD_CurrentVersionRun_abfd {
  strings:
    $key_abfd = { f8 92 [2] dc 9c [2] f7 b0 [2] d9 92 [2] cd 89 [2] c2 93 [2] dc 8e [2] de 8f [2] c5 89 [2] d9 8e [2] c5 a1 }

  condition:
    any of them
}