rule TTP_XOR_QUAD_CurrentVersionRun_ab10 {
  strings:
    $key_ab10 = { f8 7f [2] dc 71 [2] f7 5d [2] d9 7f [2] cd 64 [2] c2 7e [2] dc 63 [2] de 62 [2] c5 64 [2] d9 63 [2] c5 4c }

  condition:
    any of them
}