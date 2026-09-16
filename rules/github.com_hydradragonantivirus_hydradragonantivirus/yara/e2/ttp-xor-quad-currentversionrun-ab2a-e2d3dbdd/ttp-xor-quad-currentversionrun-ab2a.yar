rule TTP_XOR_QUAD_CurrentVersionRun_ab2a {
  strings:
    $key_ab2a = { f8 45 [2] dc 4b [2] f7 67 [2] d9 45 [2] cd 5e [2] c2 44 [2] dc 59 [2] de 58 [2] c5 5e [2] d9 59 [2] c5 76 }

  condition:
    any of them
}