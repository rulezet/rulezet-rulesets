rule TTP_XOR_QUAD_CurrentVersionRun_b2e8 {
  strings:
    $key_b2e8 = { e1 87 [2] c5 89 [2] ee a5 [2] c0 87 [2] d4 9c [2] db 86 [2] c5 9b [2] c7 9a [2] dc 9c [2] c0 9b [2] dc b4 }

  condition:
    any of them
}