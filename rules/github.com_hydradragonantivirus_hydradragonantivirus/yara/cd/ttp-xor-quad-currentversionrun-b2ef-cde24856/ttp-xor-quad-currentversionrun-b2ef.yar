rule TTP_XOR_QUAD_CurrentVersionRun_b2ef {
  strings:
    $key_b2ef = { e1 80 [2] c5 8e [2] ee a2 [2] c0 80 [2] d4 9b [2] db 81 [2] c5 9c [2] c7 9d [2] dc 9b [2] c0 9c [2] dc b3 }

  condition:
    any of them
}