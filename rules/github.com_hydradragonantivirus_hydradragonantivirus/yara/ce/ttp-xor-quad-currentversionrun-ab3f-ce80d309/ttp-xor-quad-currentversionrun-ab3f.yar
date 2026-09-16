rule TTP_XOR_QUAD_CurrentVersionRun_ab3f {
  strings:
    $key_ab3f = { f8 50 [2] dc 5e [2] f7 72 [2] d9 50 [2] cd 4b [2] c2 51 [2] dc 4c [2] de 4d [2] c5 4b [2] d9 4c [2] c5 63 }

  condition:
    any of them
}