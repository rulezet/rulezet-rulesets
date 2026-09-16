rule TTP_XOR_QUAD_CurrentVersionRun_ab0a {
  strings:
    $key_ab0a = { f8 65 [2] dc 6b [2] f7 47 [2] d9 65 [2] cd 7e [2] c2 64 [2] dc 79 [2] de 78 [2] c5 7e [2] d9 79 [2] c5 56 }

  condition:
    any of them
}