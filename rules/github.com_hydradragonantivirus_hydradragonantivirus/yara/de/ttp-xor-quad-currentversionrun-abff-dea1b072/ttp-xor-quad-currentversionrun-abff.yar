rule TTP_XOR_QUAD_CurrentVersionRun_abff {
  strings:
    $key_abff = { f8 90 [2] dc 9e [2] f7 b2 [2] d9 90 [2] cd 8b [2] c2 91 [2] dc 8c [2] de 8d [2] c5 8b [2] d9 8c [2] c5 a3 }

  condition:
    any of them
}