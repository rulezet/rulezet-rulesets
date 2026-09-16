rule TTP_XOR_QUAD_CurrentVersionRun_ab0c {
  strings:
    $key_ab0c = { f8 63 [2] dc 6d [2] f7 41 [2] d9 63 [2] cd 78 [2] c2 62 [2] dc 7f [2] de 7e [2] c5 78 [2] d9 7f [2] c5 50 }

  condition:
    any of them
}