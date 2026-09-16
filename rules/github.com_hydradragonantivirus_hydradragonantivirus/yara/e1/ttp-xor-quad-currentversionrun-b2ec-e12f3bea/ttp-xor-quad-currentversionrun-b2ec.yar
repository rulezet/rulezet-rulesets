rule TTP_XOR_QUAD_CurrentVersionRun_b2ec {
  strings:
    $key_b2ec = { e1 83 [2] c5 8d [2] ee a1 [2] c0 83 [2] d4 98 [2] db 82 [2] c5 9f [2] c7 9e [2] dc 98 [2] c0 9f [2] dc b0 }

  condition:
    any of them
}